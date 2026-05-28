/// Error types for PassM3nage
///
/// All errors are designed to fail closed: no plaintext leaked,
/// no recovery from crypto failures, clear user messages.
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    // Cryptographic errors - always fatal
    #[error("Encryption failed: invalid key or parameters")]
    EncryptionFailed,

    #[error("Decryption failed: wrong password or vault tampered")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KdfFailed,

    // Vault format errors - always fatal
    #[error("Invalid vault format: corrupted file")]
    InvalidVaultFormat,

    #[error("Unsupported vault version")]
    UnsupportedVersion,

    #[error("Invalid magic bytes")]
    InvalidMagic,

    #[error("Corrupted vault header")]
    CorruptedHeader,

    #[error("Payload length exceeds maximum")]
    PayloadTooLarge,

    // Storage errors
    #[error("Failed to read vault file")]
    ReadFailed(#[from] std::io::Error),

    #[error("Failed to write vault file")]
    WriteFailed,

    #[error("Atomic file operation failed")]
    AtomicWriteFailed,

    // Serialization errors - may indicate tampering
    #[error("Invalid JSON in vault payload")]
    InvalidPayload,

    #[error("Vault payload schema mismatch")]
    InvalidSchema,

    // Entry validation
    #[error("Invalid entry: site cannot be empty")]
    EmptySite,

    #[error("Entry not found")]
    EntryNotFound,

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault is already unlocked")]
    VaultAlreadyUnlocked,

    // Clipboard errors
    #[error("Clipboard access failed")]
    ClipboardError,

    // TUI errors
    #[error("Terminal error: {0}")]
    TerminalError(String),

    // Generic errors
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Check if error should block further operations (fail-closed)
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::EncryptionFailed
                | Error::DecryptionFailed
                | Error::KdfFailed
                | Error::InvalidVaultFormat
                | Error::UnsupportedVersion
        )
    }

    /// User-facing error message (no technical details)
    pub fn user_message(&self) -> String {
        match self {
            Error::DecryptionFailed => {
                "Wrong password or vault file is corrupted. Try again.".to_string()
            }
            Error::InvalidVaultFormat => {
                "Vault file is corrupted or not a valid PassM3nage vault.".to_string()
            }
            Error::InvalidMagic => "This file is not a PassM3nage vault.".to_string(),
            Error::UnsupportedVersion => "This vault version is not supported.".to_string(),
            _ => self.to_string(),
        }
    }
}
