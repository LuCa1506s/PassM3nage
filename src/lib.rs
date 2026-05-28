pub mod clipboard;
pub mod config;
/// PassM3nage - Security-first offline password manager library
///
/// This library provides the core password vault implementation with
/// encryption, key derivation, and secure storage.
///
/// SECURITY REQUIREMENTS:
/// - All secrets use secrecy::Secret<T>
/// - Zeroization on drop is automatic
/// - No plaintext passwords logged or printed
/// - Atomic file operations only
/// - AEAD integrity verified before decryption
pub mod crypto;
pub mod errors;
pub mod tui;
pub mod vault;

pub use config::Config;
pub use errors::{Error, Result};
