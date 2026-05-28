#![allow(dead_code)]

/// Key Derivation Function (KDF) using Argon2id
///
/// SECURITY CRITICAL:
/// - Always use random salt
/// - Never hardcode salt
/// - Validate parameters before use
/// - Use high memory cost to resist GPU/ASIC attacks
use crate::errors::{Error, Result};
use secrecy::Secret;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::randombytes;

/// Argon2id KDF parameters
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// Memory cost in KiB (64 MB recommended)
    pub memory_kb: u32,
    /// Time cost in iterations (3+ recommended)
    pub time_cost: u32,
    /// Parallelism (number of lanes)
    pub parallelism: u32,
}

impl KdfParams {
    /// Create default OWASP-recommended parameters
    pub fn default() -> Self {
        KdfParams {
            memory_kb: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
        }
    }

    /// Validate parameters are sensible
    pub fn validate(&self) -> Result<()> {
        if self.memory_kb < 8192 {
            return Err(Error::InvalidArgument(
                "Memory cost too low (< 8 MB)".to_string(),
            ));
        }
        if self.time_cost < 1 {
            return Err(Error::InvalidArgument("Time cost must be >= 1".to_string()));
        }
        if self.parallelism < 1 {
            return Err(Error::InvalidArgument(
                "Parallelism must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Generate a random 16-byte salt
pub fn generate_salt() -> [u8; 16] {
    let bytes = randombytes::randombytes(16);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes);
    salt
}

/// Derive a 32-byte key from password using Argon2id
///
/// # Arguments
/// * `password` - User password (any length)
/// * `salt` - Random 16-byte salt
/// * `params` - Argon2id parameters
///
/// # Returns
/// 32-byte secret key suitable for XChaCha20-Poly1305
///
/// # Security
/// - Uses validated Argon2id implementation from libsodium
/// - Memory-hard (resistant to GPU attacks)
/// - Time-consuming (resistant to brute force)
/// - Random salt prevents rainbow tables
pub fn derive_key(
    password: &[u8],
    salt: &[u8; 16],
    params: &KdfParams,
) -> Result<Secret<[u8; 32]>> {
    params.validate()?;

    // Convert parameters to libsodium format
    let memory = (params.memory_kb as usize)
        .saturating_mul(1024)
        .min(pwhash::argon2id13::MEMLIMIT_SENSITIVE.0);
    let opslimit = match params.time_cost {
        1 => pwhash::argon2id13::OPSLIMIT_INTERACTIVE,
        2 => pwhash::argon2id13::OPSLIMIT_MODERATE,
        _ => pwhash::argon2id13::OPSLIMIT_SENSITIVE, // >= 3
    };
    let salt_obj = pwhash::argon2id13::Salt(*salt);

    // Derive key
    let mut key = [0u8; 32];
    pwhash::argon2id13::derive_key(
        &mut key,
        password,
        &salt_obj,
        opslimit,
        pwhash::argon2id13::MemLimit(memory),
    )
    .map_err(|_| Error::KdfFailed)?;

    Ok(Secret::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt_randomness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2, "Salts should be random");
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [1u8; 16];
        let params = KdfParams {
            memory_kb: 8192,
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = derive_key(password, &salt, &params).unwrap();
        let key2 = derive_key(password, &salt, &params).unwrap();

        // Same input should produce same output
        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_derive_key_different_password() {
        let salt = [1u8; 16];
        let params = KdfParams {
            memory_kb: 8192,
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = derive_key(b"password1", &salt, &params).unwrap();
        let key2 = derive_key(b"password2", &salt, &params).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_derive_key_different_salt() {
        let password = b"password";
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let params = KdfParams {
            memory_kb: 8192,
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = derive_key(password, &salt1, &params).unwrap();
        let key2 = derive_key(password, &salt2, &params).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_key_length_always_32() {
        let password = b"test";
        let salt = generate_salt();
        let params = KdfParams::default();

        let key = derive_key(password, &salt, &params).unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_invalid_params() {
        let params = KdfParams {
            memory_kb: 100, // Too low
            time_cost: 1,
            parallelism: 1,
        };

        assert!(params.validate().is_err());
    }

    #[test]
    fn test_params_default() {
        let params = KdfParams::default();
        assert!(params.validate().is_ok());
        assert_eq!(params.memory_kb, 65536);
    }
}
