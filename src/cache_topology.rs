//! Authentication of internal cache placement relative to JavaScript mounts.
//!
//! Canonical path spelling is insufficient on case-folding filesystems: macOS
//! `realpath` may preserve the caller's case even when two spellings name the
//! same directory.  The armed boundary therefore checks both ordinary path
//! components and exact filesystem-object ancestry in both directions.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum DirectoryIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { volume: u32, file: u64 },
}

fn directory_identity(path: &Path) -> Result<DirectoryIdentity> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot identify directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "cache topology root is not a directory: {}",
        path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(DirectoryIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .with_context(|| format!("cannot pin Windows directory {}", path.display()))?;
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(directory.as_raw_handle() as _, &mut information) }
            == 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("cannot identify Windows directory {}", path.display()));
        }
        let file =
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
        Ok(DirectoryIdentity::Windows {
            volume: information.dwVolumeSerialNumber,
            file,
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("cache topology authentication is unsupported on this platform")
    }
}

fn directory_ancestry(path: &Path) -> Result<Vec<DirectoryIdentity>> {
    anyhow::ensure!(
        path.is_absolute(),
        "cache topology root is not absolute: {}",
        path.display()
    );
    let mut ancestry = Vec::new();
    for ancestor in path.ancestors() {
        // Include the root itself and fail closed if any ancestor cannot be
        // identified. Skipping one row could hide exactly the containment
        // relationship this check is meant to prove.
        ancestry.push(directory_identity(ancestor)?);
    }
    anyhow::ensure!(
        !ancestry.is_empty(),
        "cache topology root has no filesystem ancestry: {}",
        path.display()
    );
    Ok(ancestry)
}

/// Authenticate an existing internal cache root as disjoint from every
/// JavaScript-mounted backing tree and return the exact canonical spelling that
/// was checked. Callers must retain and reuse the returned path.
///
/// A cache is refused if it is equal to, beneath, or above any mounted root.
/// Exact directory identities make the comparison safe for symlink-resolved
/// endpoint aliases, case-folding aliases, and ancestry that crosses a mount
/// boundary; the component test is a conservative second check for ordinary
/// canonical paths. This does not inventory unrelated descendant bind mounts.
/// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
pub fn authenticate_internal_cache_root(
    cache_root: &Path,
    mounted_roots: &[PathBuf],
) -> Result<PathBuf> {
    anyhow::ensure!(
        !mounted_roots.is_empty(),
        "cache topology authentication requires at least one mounted backing root"
    );
    let cache_root = std::fs::canonicalize(cache_root).with_context(|| {
        format!(
            "cannot canonicalize internal cache {}",
            cache_root.display()
        )
    })?;
    let cache_ancestry = directory_ancestry(&cache_root)?;
    let cache_identity = cache_ancestry
        .first()
        .expect("nonempty directory ancestry was checked");

    for mounted_root in mounted_roots {
        let mounted_root = std::fs::canonicalize(mounted_root).with_context(|| {
            format!(
                "cannot canonicalize JavaScript-mounted backing root {}",
                mounted_root.display()
            )
        })?;
        let mounted_ancestry = directory_ancestry(&mounted_root)?;
        let mounted_identity = mounted_ancestry
            .first()
            .expect("nonempty directory ancestry was checked");
        let identity_overlap =
            cache_ancestry.contains(mounted_identity) || mounted_ancestry.contains(cache_identity);
        let component_overlap =
            cache_root.starts_with(&mounted_root) || mounted_root.starts_with(&cache_root);
        anyhow::ensure!(
            !identity_overlap && !component_overlap,
            "internal cache root {} overlaps JavaScript-mounted backing root {}",
            cache_root.display(),
            mounted_root.display()
        );
    }
    Ok(cache_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn refuses_both_cache_mount_ancestry_directions() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        let cache_inside_project = project.join(".internal-cache");
        std::fs::create_dir_all(&cache_inside_project).unwrap();
        assert!(authenticate_internal_cache_root(
            &cache_inside_project,
            std::slice::from_ref(&project),
        )
        .is_err());

        let cache = root.path().join("cache");
        let project_inside_cache = cache.join("project");
        std::fs::create_dir_all(&project_inside_cache).unwrap();
        assert!(authenticate_internal_cache_root(
            &cache,
            std::slice::from_ref(&project_inside_cache),
        )
        .is_err());
    }

    #[test]
    fn refuses_cache_equal_to_mounted_root() {
        let root = tempdir().unwrap();
        let shared = root.path().join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        assert!(authenticate_internal_cache_root(&shared, std::slice::from_ref(&shared)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_alias_of_mounted_root() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let mounted = root.path().join("mounted");
        std::fs::create_dir_all(&mounted).unwrap();
        let alias = root.path().join("mounted-alias");
        symlink(&mounted, &alias).unwrap();
        assert!(authenticate_internal_cache_root(&alias, &[mounted]).is_err());
    }

    #[test]
    fn admits_disjoint_cache_with_composed_project_and_package_mounts() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        let package = project.join("node_modules/example");
        let cache = root.path().join("runtime-cache");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&cache).unwrap();

        let checked =
            authenticate_internal_cache_root(&cache, &[project.clone(), package.clone()]).unwrap();
        assert_eq!(checked, std::fs::canonicalize(&cache).unwrap());

        let package_cache = package.join("cache");
        std::fs::create_dir_all(&package_cache).unwrap();
        assert!(authenticate_internal_cache_root(&package_cache, &[project, package],).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_case_alias_ancestry_on_case_insensitive_macos_volume() {
        let root = tempdir().unwrap();
        let mounted = root.path().join("MountedTree");
        let cache = mounted.join("Cache");
        std::fs::create_dir_all(&cache).unwrap();
        let mounted_alias = root.path().join("mountedtree");
        if !mounted_alias.exists() {
            // The test volume is case-sensitive; there is no alias to test.
            return;
        }
        assert!(authenticate_internal_cache_root(&cache, &[mounted_alias]).is_err());
    }
}
