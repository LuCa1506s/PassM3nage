#![allow(unused_imports)]

pub mod entry;
/// Vault module - high-level vault operations
///
/// Combines crypto primitives into vault operations:
/// - Create new vault
/// - Unlock existing vault
/// - Add/remove/search entries
/// - Save with atomic writes
pub mod format;
pub mod storage;

pub use entry::VaultEntry;
pub use format::VaultHeader;
