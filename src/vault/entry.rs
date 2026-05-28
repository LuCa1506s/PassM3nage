#![allow(dead_code)]

/// Vault entry structure
///
/// Represents a single password entry with site, username, password, and notes.
/// Password field is zeroized automatically on drop.
use secrecy::Zeroize;
use serde::{Deserialize, Serialize};

/// A single password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub site: String,
    pub username: String,
    #[serde(rename = "password")]
    pub password: String,
    pub notes: String,
}

impl VaultEntry {
    /// Create a new entry
    pub fn new(site: String, username: String, password: String, notes: String) -> Self {
        VaultEntry {
            site,
            username,
            password,
            notes,
        }
    }

    /// Validate entry has minimum required fields
    pub fn validate(&self) -> Result<(), String> {
        // Site is required
        if self.site.trim().is_empty() {
            return Err("Site cannot be empty".to_string());
        }

        // Reasonable size limits (prevent memory exhaustion)
        if self.site.len() > 256 {
            return Err("Site name too long".to_string());
        }
        if self.username.len() > 256 {
            return Err("Username too long".to_string());
        }
        if self.password.len() > 4096 {
            return Err("Password too long".to_string());
        }
        if self.notes.len() > 1024 {
            return Err("Notes too long".to_string());
        }

        Ok(())
    }
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        // Zero out password field
        self.password.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let entry = VaultEntry::new(
            "github.com".to_string(),
            "alice".to_string(),
            "secret123".to_string(),
            "personal account".to_string(),
        );

        assert_eq!(entry.site, "github.com");
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.password, "secret123");
        assert_eq!(entry.notes, "personal account");
    }

    #[test]
    fn test_entry_validation_empty_site() {
        let entry = VaultEntry::new(
            "".to_string(),
            "user".to_string(),
            "pass".to_string(),
            "".to_string(),
        );

        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validation_whitespace_site() {
        let entry = VaultEntry::new(
            "   ".to_string(),
            "user".to_string(),
            "pass".to_string(),
            "".to_string(),
        );

        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validation_success() {
        let entry = VaultEntry::new(
            "example.com".to_string(),
            "user".to_string(),
            "password".to_string(),
            "notes".to_string(),
        );

        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_serialization() {
        let entry = VaultEntry::new(
            "example.com".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            "test".to_string(),
        );

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: VaultEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.site, "example.com");
        assert_eq!(deserialized.username, "alice");
        assert_eq!(deserialized.password, "secret");
    }

    #[test]
    fn test_entry_serialization_empty_fields() {
        let entry = VaultEntry::new(
            "site.com".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        );

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: VaultEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.site, "site.com");
        assert_eq!(deserialized.username, "");
        assert_eq!(deserialized.password, "");
    }

    #[test]
    fn test_site_too_long() {
        let long_site = "a".repeat(300);
        let entry = VaultEntry::new(
            long_site,
            "user".to_string(),
            "pass".to_string(),
            "".to_string(),
        );

        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_password_too_long() {
        let long_pass = "a".repeat(5000);
        let entry = VaultEntry::new(
            "site.com".to_string(),
            "user".to_string(),
            long_pass,
            "".to_string(),
        );

        assert!(entry.validate().is_err());
    }
}
