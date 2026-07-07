//! File traversal, sorting, and path mapping.

use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

use crate::sign::FileEntry;

/// Path mapping: final path → source path on disk.
///
/// Used when `customize.sh` moves files (e.g. arch-specific → generic).
///
/// # Example
///
/// ```ignore
/// let mapping = FileMapping::from(("bin/zygiskd64", "bin/arm64-v8a/zygiskd"));
///
/// let mapping = FileMapping::from([
///     ("bin/zygiskd64", "bin/arm64-v8a/zygiskd"),
///     ("lib/libzygisk.so", "lib/armeabi-v7a/libzygisk.so"),
/// ]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct FileMapping {
    map: BTreeMap<String, String>,
}

impl FileMapping {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn insert<T, S>(&mut self, target_path: T, source_path: S)
    where
        T: ToString,
        S: ToString,
    {
        self.map
            .insert(target_path.to_string(), source_path.to_string());
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl From<(&str, &str)> for FileMapping {
    fn from((target, source): (&str, &str)) -> Self {
        let mut m = Self::new();
        m.insert(target, source);
        m
    }
}

impl<const N: usize> From<[(&str, &str); N]> for FileMapping {
    fn from(pairs: [(&str, &str); N]) -> Self {
        let mut m = Self::new();
        for (target, source) in pairs {
            m.insert(target, source);
        }
        m
    }
}

impl From<Vec<(&str, &str)>> for FileMapping {
    fn from(pairs: Vec<(&str, &str)>) -> Self {
        let mut m = Self::new();
        for (target, source) in pairs {
            m.insert(target, source);
        }
        m
    }
}

impl From<Vec<(String, String)>> for FileMapping {
    fn from(pairs: Vec<(String, String)>) -> Self {
        let mut m = Self::new();
        for (target, source) in pairs {
            m.insert(target, source);
        }
        m
    }
}

impl FromIterator<(String, String)> for FileMapping {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        let mut m = Self::new();
        for (target, source) in iter {
            m.insert(target, source);
        }
        m
    }
}

impl<'a> FromIterator<(&'a str, &'a str)> for FileMapping {
    fn from_iter<I: IntoIterator<Item = (&'a str, &'a str)>>(iter: I) -> Self {
        let mut m = Self::new();
        for (target, source) in iter {
            m.insert(target, source);
        }
        m
    }
}

impl IntoIterator for FileMapping {
    type Item = (String, String);
    type IntoIter = std::collections::btree_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}

impl<'a> IntoIterator for &'a FileMapping {
    type Item = (&'a str, &'a str);
    type IntoIter = std::iter::Map<
        std::collections::btree_map::Iter<'a, String, String>,
        fn((&'a String, &'a String)) -> (&'a str, &'a str),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl From<FileMapping> for Vec<(String, String)> {
    fn from(mapping: FileMapping) -> Self {
        mapping.map.into_iter().collect()
    }
}

impl<'a> From<&'a FileMapping> for Vec<(&'a str, &'a str)> {
    fn from(mapping: &'a FileMapping) -> Self {
        mapping
            .map
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
}

/// Load and sort all files under `folder`, with optional path mapping and ignore rules.
///
/// `ignore_prefixes`: relative path prefixes to skip.
/// `ignore_names`: exact relative paths to skip.
/// `mapping`: optional [`FileMapping`]; mapped entries take priority.
///
/// # Example
///
/// ```ignore
/// let entries = machikado_rs::load_folder_files(dir, &[], &["machikado", "mazoku"], None)?;
///
/// let mapping = FileMapping::from(("bin/zygiskd64", "bin/arm64-v8a/zygiskd"));
/// let entries = machikado_rs::load_folder_files(dir, &[], &["machikado", "mazoku"], Some(&mapping))?;
/// ```
pub fn load_folder_files(
    folder: &Path,
    ignore_prefixes: &[&str],
    ignore_names: &[&str],
    mapping: Option<&FileMapping>,
) -> std::io::Result<Vec<FileEntry>> {
    let mut entries = Vec::new();

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

        if let Some(m) = mapping
            && (m.map.values().any(|s| s == &relative_path) || m.map.contains_key(&relative_path))
        {
            continue;
        }

        if ignore_prefixes.iter().any(|p| relative_path.starts_with(p)) {
            continue;
        }
        if ignore_names.iter().any(|n| relative_path == *n) {
            continue;
        }

        let content = std::fs::read(entry.path())?;
        entries.push(FileEntry {
            relative_path,
            content,
        });
    }

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

        assert_eq!(paths, vec!["bin/zygiskd64", "module.prop"]);
    }

    #[test]
    fn test_mapping_from_single_pair() {
        let m = FileMapping::from(("bin/foo", "bin/arm64-v8a/foo"));
        assert_eq!(m.len(), 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn test_mapping_from_array() {
        let m = FileMapping::from([
            ("bin/zygiskd64", "bin/arm64-v8a/zygiskd"),
            ("bin/zygiskd32", "bin/armeabi-v7a/zygiskd"),
        ]);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn test_mapping_from_iterator() {
        let pairs = vec![
            ("a.txt".to_string(), "src/a.txt".to_string()),
            ("b.txt".to_string(), "src/b.txt".to_string()),
        ];
        let m: FileMapping = pairs.into_iter().collect();
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn test_mapping_from_empty_array() {
        let m = FileMapping::from([]);
        assert!(m.is_empty());
    }

    #[test]
    fn test_mapping_into_vec() {
        let mut m = FileMapping::new();
        m.insert("a", "src/a");
        m.insert("b", "src/b");

        let vec: Vec<(String, String)> = m.clone().into();
        assert_eq!(
            vec,
            vec![
                ("a".to_string(), "src/a".to_string()),
                ("b".to_string(), "src/b".to_string()),
            ]
        );

        let vec_ref: Vec<(&str, &str)> = (&m).into();
        assert_eq!(vec_ref, vec![("a", "src/a"), ("b", "src/b")]);
    }

    #[test]
    fn test_mapping_into_iter() {
        let mut m = FileMapping::new();
        m.insert("a", "src/a");
        m.insert("b", "src/b");

        let collected: Vec<(String, String)> = m.into_iter().collect();
        assert_eq!(
            collected,
            vec![
                ("a".to_string(), "src/a".to_string()),
                ("b".to_string(), "src/b".to_string()),
            ]
        );
    }

    #[test]
    fn test_mapping_ref_iter() {
        let mut m = FileMapping::new();
        m.insert("a", "src/a");

        let collected: Vec<(&str, &str)> = (&m).into_iter().collect();
        assert_eq!(collected, vec![("a", "src/a")]);
    }

    #[test]
    fn test_mapping_target_exists_on_disk_no_duplicate() {
        let dir = temp_dir();
        let _guard = Cleanup(Some(dir.clone()));

        write_file(&dir, "module.prop", b"modified");
        write_file(&dir, "module.prop.orig", b"original");

        let mapping = FileMapping::from(("module.prop", "module.prop.orig"));

        let entries = load_folder_files(&dir, &[], &[], Some(&mapping)).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
        let contents: Vec<&[u8]> = entries.iter().map(|e| e.content.as_slice()).collect();

        assert_eq!(paths, vec!["module.prop"]);
        assert_eq!(contents, vec![b"original" as &[u8]]);
    }

    struct Cleanup(Option<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(_dir) = self.0.take() {}
        }
    }
}
