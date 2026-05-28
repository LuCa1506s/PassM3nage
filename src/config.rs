/// Configuration defaults for PassM3nage
///
/// These are cryptographic and UX defaults. Users can override
/// some parameters at runtime (but not recommended for security-critical ones).

#[derive(Debug, Clone)]
pub struct Config {
    /// Argon2id memory cost in KiB (65536 = 64 MB)
    pub kdf_memory_kb: u32,

    /// Argon2id time cost (iterations)
    pub kdf_time_cost: u32,

    /// Argon2id parallelism (lanes)
    pub kdf_parallelism: u32,

    /// Clipboard auto-clear timeout in seconds
    pub clipboard_timeout_secs: u64,

    /// Maximum vault payload size (100 MB)
    pub max_payload_bytes: u32,
}

impl Config {
    /// Create default configuration (secure but reasonably fast)
    pub fn default() -> Self {
        Config {
            // These values are from OWASP recommendation
            kdf_memory_kb: 65536, // 64 MB
            kdf_time_cost: 3,     // ~3 seconds per unlock
            kdf_parallelism: 4,
            clipboard_timeout_secs: 30,
            max_payload_bytes: 100 * 1024 * 1024, // 100 MB
        }
    }

    /// Create fast configuration (less secure, for testing)
    #[cfg(test)]
    pub fn fast() -> Self {
        Config {
            kdf_memory_kb: 8192, // 8 MB
            kdf_time_cost: 1,
            kdf_parallelism: 1,
            clipboard_timeout_secs: 5,
            max_payload_bytes: 10 * 1024 * 1024, // 10 MB
        }
    }

    /// Validate configuration is sensible
    pub fn validate(&self) -> Result<(), String> {
        if self.kdf_memory_kb < 8192 {
            return Err("KDF memory must be at least 8 MB".to_string());
        }
        if self.kdf_time_cost < 1 {
            return Err("KDF time cost must be at least 1".to_string());
        }
        if self.kdf_parallelism < 1 {
            return Err("KDF parallelism must be at least 1".to_string());
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fast_config_valid() {
        let config = Config::fast();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let mut config = Config::default();
        config.kdf_memory_kb = 1024; // Too small
        assert!(config.validate().is_err());
    }
}
