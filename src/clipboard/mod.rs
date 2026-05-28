#![allow(unused_imports)]

/// Clipboard module - secure password copying
///
/// Passwords are copied to system clipboard with auto-clear after timeout.
pub mod utils;

pub use utils::copy_password;
