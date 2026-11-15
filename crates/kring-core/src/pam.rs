//! Detection of the PAM integration that auto-unlocks gnome-keyring at login.

use std::path::{Path, PathBuf};

/// Module name looked for in PAM service files.
const PAM_MODULE: &str = "pam_gnome_keyring.so";

/// Result of scanning the PAM configuration directory.
#[derive(Debug, Clone, PartialEq)]
pub struct PamStatus {
    /// True when at least one PAM file enables `pam_gnome_keyring.so`.
    pub configured: bool,
    /// Full paths of the files that enable the module, sorted by file name.
    pub files: Vec<PathBuf>,
}

/// Scans `pam_dir` (non-recursive) for files with an active `pam_gnome_keyring.so` line.
///
/// Comment lines are ignored and unreadable files are skipped.
pub fn pam_status(pam_dir: &Path) -> PamStatus {
    let Ok(entries) = std::fs::read_dir(pam_dir) else {
        return PamStatus {
            configured: false,
            files: Vec::new(),
        };
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| _enables_module(p))
        .collect();
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    PamStatus {
        configured: !files.is_empty(),
        files,
    }
}

/// Returns true when the file has a non-comment line mentioning the module.
fn _enables_module(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#') && line.contains(PAM_MODULE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a fresh empty temp directory for a test.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kring-pam-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Active lines count, commented ones do not.
    #[test]
    fn detects_active_lines_only() {
        let dir = temp_dir("active");
        std::fs::write(dir.join("sddm"), "-auth optional pam_gnome_keyring.so\n").unwrap();
        std::fs::write(dir.join("other"), "# pam_gnome_keyring.so\n").unwrap();
        std::fs::write(
            dir.join("login"),
            "  session optional pam_gnome_keyring.so auto_start\n",
        )
        .unwrap();
        std::fs::create_dir(dir.join("subdir")).unwrap();
        let status = pam_status(&dir);
        assert!(status.configured);
        assert_eq!(status.files, vec![dir.join("login"), dir.join("sddm")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty or missing directory is not configured.
    #[test]
    fn empty_or_missing_dir_not_configured() {
        let dir = temp_dir("empty");
        let status = pam_status(&dir);
        assert_eq!(
            status,
            PamStatus {
                configured: false,
                files: vec![]
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!pam_status(&dir).configured);
    }
}
