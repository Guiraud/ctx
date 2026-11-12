//! macOS fallback for appends to files that were already dirty when watched.
//! Metadata only: no content hashing and no symlink traversal.
//! The dependency's PollWatcher compares whole-second mtimes, not file lengths.
//!
//! Cost model: provider roots hold tens of thousands of cold transcripts, but
//! only a handful of live journals are appended at any time. Every
//! `POLL_INTERVAL` the watcher stats only the hot files: regular files whose
//! mtime falls inside `HOT_WINDOW`, or that changed since the last pass. The
//! full recursive inventory runs every `FULL_SCAN_EVERY` passes. That
//! inventory refreshes the hot set and remains the backstop for anything
//! native notifications missed.
//!
//! Latency bound: an append to a hot file is seen within `POLL_INTERVAL`
//! (5 s). One case is slower: a writer already open when watching started,
//! then idle for longer than `HOT_WINDOW`, then appending again. Its file is
//! cold, FSEvents does not report it, and the next full inventory sees it,
//! within `POLL_INTERVAL * FULL_SCAN_EVERY` (60 s).
use notify::{
    event::{CreateKind, MetadataKind, ModifyKind, RemoveKind},
    Event, EventKind, RecursiveMode,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime},
};

type Handler = Arc<dyn Fn(notify::Result<Event>) + Send + Sync>;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Full inventories run once every this many polls (60 s at the default interval).
const FULL_SCAN_EVERY: u32 = 12;
/// Files modified this recently are treated as possibly open for append.
const HOT_WINDOW: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
    kind: u8,
}

impl Stamp {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            modified: metadata.modified().ok(),
            len: metadata.len(),
            kind: if metadata.file_type().is_dir() {
                1
            } else if metadata.file_type().is_symlink() {
                2
            } else {
                0
            },
        }
    }

    fn is_hot(&self, now: SystemTime) -> bool {
        self.kind == 0
            && self.modified.is_some_and(|modified| {
                now.duration_since(modified)
                    .map_or(true, |age| age <= HOT_WINDOW)
            })
    }
}

struct Root {
    recursive: bool,
    entries: BTreeMap<PathBuf, Stamp>,
    hot: BTreeSet<PathBuf>,
}

impl Root {
    fn new(recursive: bool, entries: BTreeMap<PathBuf, Stamp>) -> Self {
        let hot = hot_set(&entries, SystemTime::now());
        Self {
            recursive,
            entries,
            hot,
        }
    }
}

fn hot_set(entries: &BTreeMap<PathBuf, Stamp>, now: SystemTime) -> BTreeSet<PathBuf> {
    entries
        .iter()
        .filter(|(_, stamp)| stamp.is_hot(now))
        .map(|(path, _)| path.clone())
        .collect()
}

/// Returns false when cancellation was observed.
fn full_pass(
    path: &Path,
    root: &mut Root,
    handler: &Handler,
    canceled: &impl Fn() -> bool,
) -> bool {
    let current = match scan(path, root.recursive, canceled) {
        Ok(current) => current,
        Err(error) => {
            if canceled() {
                return false;
            }
            handler(Err(error));
            return true;
        }
    };
    for (path, stamp) in &current {
        if canceled() {
            return false;
        }
        let kind = match root.entries.get(path) {
            None => Some(EventKind::Create(CreateKind::Any)),
            Some(old) if old != stamp => Some(EventKind::Modify(ModifyKind::Metadata(
                MetadataKind::WriteTime,
            ))),
            _ => None,
        };
        if let Some(kind) = kind {
            handler(Ok(Event::new(kind).add_path(path.clone())));
        }
    }
    for path in root
        .entries
        .keys()
        .filter(|path| !current.contains_key(*path))
    {
        if canceled() {
            return false;
        }
        handler(Ok(
            Event::new(EventKind::Remove(RemoveKind::Any)).add_path(path.clone())
        ));
    }
    root.hot = hot_set(&current, SystemTime::now());
    root.entries = current;
    true
}

/// Stats only hot files. Returns false when cancellation was observed.
fn hot_pass(root: &mut Root, handler: &Handler, canceled: &impl Fn() -> bool) -> bool {
    let now = SystemTime::now();
    let mut cooled = Vec::new();
    for path in &root.hot {
        if canceled() {
            return false;
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                let stamp = Stamp::of(&metadata);
                let changed = root.entries.get(path) != Some(&stamp);
                if changed {
                    handler(Ok(Event::new(EventKind::Modify(ModifyKind::Metadata(
                        MetadataKind::WriteTime,
                    )))
                    .add_path(path.clone())));
                } else if !stamp.is_hot(now) {
                    cooled.push(path.clone());
                }
                root.entries.insert(path.clone(), stamp);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                handler(Ok(
                    Event::new(EventKind::Remove(RemoveKind::Any)).add_path(path.clone())
                ));
                root.entries.remove(path);
                cooled.push(path.clone());
            }
            Err(error) => handler(Err(notify::Error::io(error).add_path(path.clone()))),
        }
    }
    for path in cooled {
        root.hot.remove(&path);
    }
    true
}
pub(super) struct MetadataWatcher {
    roots: Arc<Mutex<BTreeMap<PathBuf, Root>>>,
    stop: mpsc::Sender<()>,
    stopping: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl MetadataWatcher {
    pub(super) fn new(handler: Handler) -> notify::Result<Self> {
        let roots = Arc::new(Mutex::new(BTreeMap::<PathBuf, Root>::new()));
        let watched = Arc::clone(&roots);
        let stopping = Arc::new(AtomicBool::new(false));
        let canceled = Arc::clone(&stopping);
        let (stop, receive) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("ctx-metadata-watch".to_owned())
            .spawn(move || {
                let is_canceled = || canceled.load(Ordering::Acquire);
                let mut pass = 0_u32;
                while matches!(
                    receive.recv_timeout(POLL_INTERVAL),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    pass = pass.wrapping_add(1);
                    let full = pass.is_multiple_of(FULL_SCAN_EVERY);
                    let mut roots = watched
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    for (path, root) in roots.iter_mut() {
                        if is_canceled() {
                            return;
                        }
                        let completed = if full {
                            full_pass(path, root, &handler, &is_canceled)
                        } else {
                            hot_pass(root, &handler, &is_canceled)
                        };
                        if !completed {
                            return;
                        }
                    }
                }
            })
            .map_err(notify::Error::io)?;
        Ok(Self {
            roots,
            stop,
            stopping,
            worker: Some(worker),
        })
    }
    pub(super) fn watch(&mut self, path: &Path, mode: RecursiveMode) -> notify::Result<()> {
        let recursive = matches!(mode, RecursiveMode::Recursive);
        let entries = scan(path, recursive, || self.stopping.load(Ordering::Acquire))?;
        self.roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf(), Root::new(recursive, entries));
        Ok(())
    }
    pub(super) fn unwatch(&mut self, path: &Path) -> notify::Result<()> {
        self.roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(path);
        Ok(())
    }

    pub(super) fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for MetadataWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}
fn scan(
    root: &Path,
    recursive: bool,
    canceled: impl Fn() -> bool,
) -> notify::Result<BTreeMap<PathBuf, Stamp>> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((path, depth)) = pending.pop() {
        if canceled() {
            return Err(notify::Error::generic("metadata watch stopped"));
        }
        if entries.len() >= 100_000 || depth > 64 {
            return Err(
                notify::Error::generic("metadata watch inventory exceeds its bound").add_path(path),
            );
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(notify::Error::io(error).add_path(path)),
        };
        let directory = metadata.file_type().is_dir();
        entries.insert(path.clone(), Stamp::of(&metadata));
        if directory && (recursive || depth == 0) {
            for child in
                std::fs::read_dir(&path).map_err(|e| notify::Error::io(e).add_path(path.clone()))?
            {
                let child = child.map_err(notify::Error::io)?;
                if canceled() {
                    return Err(notify::Error::generic("metadata watch stopped"));
                }
                if pending.len() + entries.len() >= 100_000 {
                    return Err(notify::Error::generic(
                        "metadata watch inventory exceeds its bound",
                    )
                    .add_path(path));
                }
                pending.push((child.path(), depth + 1));
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn same_timestamp_append_is_reported() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temp.path().join("active.jsonl");
        let mut writer = std::fs::File::create(&path).unwrap();
        writer.write_all(b"first\n").unwrap();
        writer.flush().unwrap();
        let modified = writer.metadata().unwrap().modified().unwrap();
        let (tx, rx) = mpsc::channel();
        let mut watcher = MetadataWatcher::new(Arc::new(move |event| {
            let _ = tx.send(event);
        }))
        .unwrap();
        watcher
            .watch(temp.path(), RecursiveMode::Recursive)
            .unwrap();
        writer.write_all(b"second\n").unwrap();
        writer.flush().unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let event = rx
            .recv_timeout(Duration::from_secs(8))
            .expect("same-time size change must be observed")
            .unwrap();
        assert!(event.paths.contains(&path));
    }

    fn collecting_handler() -> (Handler, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let handler: Handler = Arc::new(move |event| {
            if let Ok(event) = event {
                let _ = tx.lock().unwrap().send(event);
            }
        });
        (handler, rx)
    }

    fn age(path: &Path, by: Duration) {
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - by))
            .unwrap();
    }

    #[test]
    fn hot_pass_stats_only_recent_files() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let live = temp.path().join("live.jsonl");
        let cold = temp.path().join("cold.jsonl");
        std::fs::write(&live, b"one\n").unwrap();
        std::fs::write(&cold, b"one\n").unwrap();
        age(&cold, HOT_WINDOW * 2);
        let mut root = Root::new(true, scan(temp.path(), true, || false).unwrap());
        assert!(root.hot.contains(&live));
        assert!(!root.hot.contains(&cold));

        let (handler, rx) = collecting_handler();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&live)
            .unwrap()
            .write_all(b"two\n")
            .unwrap();
        assert!(hot_pass(&mut root, &handler, &|| false));
        let paths: Vec<_> = rx.try_iter().flat_map(|event| event.paths).collect();
        assert_eq!(paths, vec![live.clone()]);

        // A cold file is left to the periodic full inventory.
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&cold)
            .unwrap();
        writer.write_all(b"two\n").unwrap();
        age(&cold, HOT_WINDOW * 2);
        assert!(hot_pass(&mut root, &handler, &|| false));
        assert_eq!(rx.try_iter().count(), 0);
        assert!(full_pass(temp.path(), &mut root, &handler, &|| false));
        let paths: Vec<_> = rx.try_iter().flat_map(|event| event.paths).collect();
        assert!(paths.contains(&cold));
    }

    #[test]
    fn hot_pass_reports_removal_and_cools_idle_files() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let removed = temp.path().join("removed.jsonl");
        let idle = temp.path().join("idle.jsonl");
        std::fs::write(&removed, b"x\n").unwrap();
        std::fs::write(&idle, b"x\n").unwrap();
        let mut root = Root::new(true, scan(temp.path(), true, || false).unwrap());
        let (handler, rx) = collecting_handler();

        std::fs::remove_file(&removed).unwrap();
        // Same length, older mtime: changed once, then cools on the next pass.
        age(&idle, HOT_WINDOW * 2);
        assert!(hot_pass(&mut root, &handler, &|| false));
        let events: Vec<_> = rx.try_iter().collect();
        assert!(events.iter().any(|event| {
            matches!(event.kind, EventKind::Remove(_)) && event.paths.contains(&removed)
        }));
        assert!(!root.hot.contains(&removed));
        assert!(!root.entries.contains_key(&removed));
        assert!(root.hot.contains(&idle));
        assert!(hot_pass(&mut root, &handler, &|| false));
        assert!(!root.hot.contains(&idle));
    }

    #[test]
    fn recursive_scan_does_not_follow_symlink_descendants() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("not-a-source"), b"private").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let entries = scan(&root, true, || false).unwrap();
        assert!(entries.contains_key(&root.join("link")));
        assert!(!entries.contains_key(&root.join("link/not-a-source")));
    }

    #[test]
    fn scan_checks_shutdown_while_enumerating_children() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..8 {
            std::fs::write(temp.path().join(index.to_string()), b"").unwrap();
        }
        let checks = std::cell::Cell::new(0);
        let result = scan(temp.path(), true, || {
            checks.set(checks.get() + 1);
            checks.get() == 3
        });
        assert!(result.is_err());
        assert_eq!(checks.get(), 3);
    }

    #[test]
    fn shutdown_interrupts_the_idle_poll_wait() {
        let mut watcher = MetadataWatcher::new(Arc::new(|_| {})).unwrap();
        let start = std::time::Instant::now();
        watcher.stop();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(watcher.worker.is_none());
        watcher.stop();
    }

    #[test]
    fn scan_preserves_nonrecursive_and_depth_bounds() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("grandchild"), b"").unwrap();
        let shallow = scan(temp.path(), false, || false).unwrap();
        assert!(shallow.contains_key(&child));
        assert!(!shallow.contains_key(&child.join("grandchild")));
        let mut next = child;
        for _ in 0..64 {
            next = next.join("nested");
            std::fs::create_dir(&next).unwrap();
        }
        assert!(scan(temp.path(), true, || false).is_err());
    }
}
