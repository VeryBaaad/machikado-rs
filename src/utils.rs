//! File utilities: folder traversal, sorting, and path mapping.

use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

use crate::sign::FileEntry;

/// File mapping table: defines how source paths map to final paths.
///
/// Used when a Magisk module's `customize.sh` moves files during installation
/// (e.g. architecture-specific paths → generic paths).
/// key = final path (path signed into machikado), value = source path (actual file on disk).
///
/// # Example
///
/// ```ignore
/// let mut mapping = FileMapping::new();
/// // final path ← source path
/// mapping.insert("bin/zygiskd64", "bin/arm64-v8a/zygiskd");
/// mapping.insert("lib/libzygisk.so", "lib/armeabi-v7a/libzygisk.so");
/// ```
#[derive(Debug, Clone, Default)]
pub struct FileMapping {
    map: BTreeMap<String, String>,
}

impl FileMapping {
    /// Create an empty mapping.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Add a mapping entry.
    ///
    /// `target_path`: final path (path on device, used for sorting and signing).
    /// `source_path`: source path (actual file location in the module directory).
    pub fn insert(&mut self, target_path: &str, source_path: &str) {
        self.map
            .insert(target_path.to_string(), source_path.to_string());
    }

    /// Number of entries in the mapping.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Recursively load all files from a folder, sorted by relative path (using `/` separator).
///
/// `mapping`: optional file mapping. When provided, mapped entries take priority:
/// the final path becomes [`FileEntry::relative_path`] and content is read from the
/// source path. The directory walk skips source paths already covered by the mapping
/// to avoid duplicates. Pass `None` for the original behaviour.
///
/// `ignore_prefixes`: relative path prefixes to skip (e.g. `["subdir_to_skip"]`).
/// `ignore_names`: exact relative paths to skip (e.g. `["machikado", "mazoku"]`).
///
/// Sort order matches ZygiskNext's `TreeSet` behavior (lexicographic string sort).
///
/// # Example
///
/// ```ignore
/// // Without mapping (same as before)
/// let entries = machikado_rs::load_folder_files(module_dir, &[], &["machikado", "mazoku"], None)?;
///
/// // With mapping
/// let mut mapping = machikado_rs::FileMapping::new();
/// mapping.insert("bin/zygiskd64", "bin/arm64-v8a/zygiskd");
/// let entries = machikado_rs::load_folder_files(module_dir, &[], &["machikado", "mazoku"], Some(&mapping))?;
/// ```
pub fn load_folder_files(
    folder: &Path,
    ignore_prefixes: &[&str],
    ignore_names: &[&str],
    mapping: Option<&FileMapping>,
) -> std::io::Result<Vec<FileEntry>> {
    let mut entries = Vec::new();

    // ── 1. Process mapped entries ──────────────────────────────────
    if let Some(m) = mapping {
        for (target_path, source_path) in &m.map {
            let full_source = folder.join(source_path);
            let content = std::fs::read(&full_source).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to read mapped source '{}' (→ target '{}'): {}",
                        source_path, target_path, e
                    ),
                )
            })?;
            entries.push(FileEntry {
                relative_path: target_path.clone(),
                content,
            });
        }
    }

    // ── 2. Walk directory for unmapped files ───────────────────────
    for entry in WalkDir::new(folder)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative_path = entry
            .path()
            .strip_prefix(folder)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");

        // Skip source paths already covered by the mapping
        if let Some(m) = mapping
            && m.map.values().any(|s| s == &relative_path)
        {
            continue;
        }

        // Check prefix-based ignore
        if ignore_prefixes.iter().any(|p| relative_path.starts_with(p)) {
            continue;
        }
        // Check exact-name ignore
        if ignore_names.iter().any(|n| relative_path == *n) {
            continue;
        }

        let content = std::fs::read(entry.path())?;
        entries.push(FileEntry {
            relative_path,
            content,
        });
    }

    // ── 3. Sort by final path ──────────────────────────────────────
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("machikado_test_{}_{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, rel: &str, content: &[u8]) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    #[test]
    fn test_load_folder_ignore_prefix() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        write_file(&dir, "keep.txt", b"keep");
        write_file(&dir, "skip/config.txt", b"skip");
        write_file(&dir, "skip/nested/data.bin", b"data");

        // Exclude the "skip/" prefix
        let entries = load_folder_files(&dir, &["skip"], &[], None).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["keep.txt"]);
    }

    #[test]
    fn test_load_folder_ignore_name() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        write_file(&dir, "a.txt", b"a");
        write_file(&dir, "b.txt", b"b");
        write_file(&dir, "sub/c.txt", b"c");

        // Exclude a specific file by exact name
        let entries = load_folder_files(&dir, &[], &["b.txt"], None).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["a.txt", "sub/c.txt"]);
    }

    #[test]
    fn test_load_folder_ignore_combined() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        write_file(&dir, "keep.txt", b"k");
        write_file(&dir, "skip_prefix/data.txt", b"d");
        write_file(&dir, "skip_exact.txt", b"e");

        // Both prefix and exact-name ignores work together
        let entries = load_folder_files(&dir, &["skip_prefix"], &["skip_exact.txt"], None).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["keep.txt"]);
    }

    #[test]
    fn test_load_folder_sorts() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        write_file(&dir, "c.txt", b"c");
        write_file(&dir, "a.txt", b"a");
        write_file(&dir, "b/1.txt", b"b1");
        write_file(&dir, "b/0.txt", b"b0");

        let entries = load_folder_files(&dir, &[], &[], None).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["a.txt", "b/0.txt", "b/1.txt", "c.txt"]);
    }

    #[test]
    fn test_load_folder_with_mapping() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        // Source directory has arch-specific subdirectories
        write_file(&dir, "bin/arm64-v8a/zygiskd", b"d64");
        write_file(&dir, "bin/armeabi-v7a/zygiskd", b"d32");
        write_file(&dir, "module.prop", b"prop");
        write_file(&dir, "post-fs-data.sh", b"post");

        let mut mapping = FileMapping::new();
        mapping.insert("bin/zygiskd64", "bin/arm64-v8a/zygiskd");
        mapping.insert("bin/zygiskd32", "bin/armeabi-v7a/zygiskd");

        let entries = load_folder_files(&dir, &[], &[], Some(&mapping)).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        let contents: Vec<&[u8]> = entries.iter().map(|e| e.content.as_slice()).collect();

        // Mapped files appear under their final path; unmapped files as-is; sorted by final path
        assert_eq!(
            paths,
            vec![
                "bin/zygiskd32",
                "bin/zygiskd64",
                "module.prop",
                "post-fs-data.sh"
            ]
        );
        assert_eq!(contents, vec![b"d32" as &[u8], b"d64", b"prop", b"post"]);
    }

    #[test]
    fn test_load_folder_mapping_skips_source_paths() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        write_file(&dir, "bin/arm64-v8a/zygiskd", b"d64");
        write_file(&dir, "module.prop", b"prop");

        let mut mapping = FileMapping::new();
        mapping.insert("bin/zygiskd64", "bin/arm64-v8a/zygiskd");

        let entries = load_folder_files(&dir, &[], &[], Some(&mapping)).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();

        // Source path bin/arm64-v8a/zygiskd must not appear (mapping covers it)
        assert_eq!(paths, vec!["bin/zygiskd64", "module.prop"]);
    }

    /// RAII guard to clean up temp dir on drop
    struct Cleanup(Option<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(_dir) = self.0.take() {
                // let _ = fs::remove_dir_all(&dir);
            }
        }
    }
}
