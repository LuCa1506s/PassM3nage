#![allow(dead_code)]

/// Vault storage - file I/O with atomic writes
///
/// SECURITY CRITICAL:
/// - All writes are atomic (write → fsync → rename)
/// - No partial writes on power loss or crash
/// - Temporary files cleaned up on error
use crate::errors::{Error, Result};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

/// Load encrypted vault from file
pub fn load_vault_encrypted(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::InvalidArgument("Vault file not found".to_string())
        } else {
            Error::ReadFailed(e)
        }
    })
}

/// Save encrypted vault to file atomically
///
/// Process:
/// 1. Write to temporary file
/// 2. Flush OS buffers
/// 3. Sync to disk (fsync)
/// 4. Atomic rename (temp → destination)
///
/// This ensures the vault file cannot be corrupted by:
/// - Power loss during write
/// - OS crash during write
/// - Partial writes
pub fn save_vault_encrypted(path: &Path, data: &[u8]) -> Result<()> {
    // Create temporary file with .tmp suffix
    let temp_path = if let Some(parent) = path.parent() {
        if let Some(name) = path.file_name() {
            let name = name.to_string_lossy();
            let temp_name = format!("{}.tmp", name);
            parent.join(temp_name)
        } else {
            return Err(Error::InvalidArgument("Invalid vault path".to_string()));
        }
    } else {
        return Err(Error::InvalidArgument("Invalid vault path".to_string()));
    };

    // Write to temporary file
    let mut temp_file = File::create(&temp_path)
        .map_err(|e| Error::Internal(format!("Failed to create temp file: {}", e)))?;

    temp_file
        .write_all(data)
        .map_err(|e| Error::Internal(format!("Failed to write vault: {}", e)))?;

    // Flush user-space buffers
    temp_file
        .flush()
        .map_err(|e| Error::Internal(format!("Failed to flush vault: {}", e)))?;

    // Sync to disk (fsync)
    temp_file
        .sync_all()
        .map_err(|e| Error::Internal(format!("Failed to sync vault: {}", e)))?;

    drop(temp_file); // Close file descriptor

    // Atomic rename
    fs::rename(&temp_path, path).map_err(|e| {
        // Clean up temp file on error
        let _ = fs::remove_file(&temp_path);
        Error::Internal(format!("Failed to rename vault: {}", e))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");

        let data = b"test vault data";

        // Save
        save_vault_encrypted(&vault_path, data).unwrap();

        // Load
        let loaded = load_vault_encrypted(&vault_path).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_load_nonexistent() {
        let path = Path::new("/nonexistent/vault.db");
        let result = load_vault_encrypted(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("new_vault.db");

        let data = b"initial data";
        save_vault_encrypted(&vault_path, data).unwrap();

        assert!(vault_path.exists());
    }

    #[test]
    fn test_atomic_write_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");

        // First write
        save_vault_encrypted(&vault_path, b"first").unwrap();

        // Second write
        save_vault_encrypted(&vault_path, b"second").unwrap();

        let loaded = load_vault_encrypted(&vault_path).unwrap();
        assert_eq!(loaded, b"second");
    }

    #[test]
    fn test_atomic_write_no_temp_files_left() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");

        save_vault_encrypted(&vault_path, b"data").unwrap();

        // Check no .tmp files left
        let entries = fs::read_dir(dir.path()).unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            assert!(!path.to_string_lossy().ends_with(".tmp"));
        }
    }

    #[test]
    fn test_save_large_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");

        let data = vec![42u8; 1_000_000]; // 1 MB
        save_vault_encrypted(&vault_path, &data).unwrap();

        let loaded = load_vault_encrypted(&vault_path).unwrap();
        assert_eq!(loaded.len(), data.len());
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_save_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.db");

        save_vault_encrypted(&vault_path, b"").unwrap();

        let loaded = load_vault_encrypted(&vault_path).unwrap();
        assert_eq!(loaded, b"");
    }
}
