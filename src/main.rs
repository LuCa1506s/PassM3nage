mod clipboard;
mod config;
/// PassM3nage: Security-first offline password manager
///
/// This module provides the core password vault implementation with
/// encryption, key derivation, and secure storage.
///
/// SECURITY REQUIREMENTS:
/// - All secrets use secrecy::Secret<T>
/// - Zeroization on drop is automatic
/// - No plaintext passwords logged or printed
/// - Atomic file operations only
/// - AEAD integrity verified before decryption
mod crypto;
mod errors;
mod tui;
mod vault;

pub use config::Config;
pub use errors::{Error, Result};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::Terminal;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Import crypto functions
use crate::crypto::cipher;
use crate::crypto::kdf;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    service: String,
    #[serde(with = "hex_vec")]
    username_ciphertext: Vec<u8>,
    #[serde(with = "hex_array_24")]
    username_nonce: [u8; 24],
    #[serde(with = "hex_vec")]
    password_ciphertext: Vec<u8>,
    #[serde(with = "hex_array_24")]
    password_nonce: [u8; 24],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    log: bool,
    entries: Vec<StoredEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum VaultDiskFormat {
    Current(VaultFile),
    Legacy(Vec<StoredEntry>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TechFile {
    #[serde(with = "hex_array_16")]
    salt: [u8; 16],
    #[serde(with = "hex_vec")]
    check_ciphertext: Vec<u8>,
    #[serde(with = "hex_array_24")]
    check_nonce: [u8; 24],
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ::hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod hex_array_24 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 24], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 24], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = ::hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("expected 24 bytes, got {}", bytes.len()))
        })
    }
}

mod hex_array_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = ::hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("expected 16 bytes, got {}", bytes.len()))
        })
    }
}

#[derive(Debug, Clone)]
struct PasswordEntry {
    service: String,
    username: String,
    password: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AppScreen {
    SetupPassword,
    LoginPassword,
    SecurityRisk,
    Menu,
    AddEntry,
    BackupVault,
    UploadBackup,
    ViewEntries,
    SelectEntry,
    ShowPassword,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DuplicatePrompt {
    Overwrite,
    SaveCopy,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EditPrompt {
    Auth,
    Edit,
}

#[derive(Debug)]
struct AppState {
    screen: AppScreen,
    entries: Vec<PasswordEntry>,
    stored_entries: Vec<StoredEntry>,
    input_buffers: [String; 3], // [service, username, password]
    input_field: usize,         // 0 = service, 1 = username, 2 = password
    selected_index: usize,
    search_query: String,
    search_field_active: bool,
    confirm_delete: bool,
    pending_delete_index: Option<usize>,
    edit_prompt: Option<EditPrompt>,
    edit_index: Option<usize>,
    edit_auth_buffer: String,
    edit_buffers: [String; 2], // [username, password]
    edit_field: usize,
    duplicate_prompt: Option<DuplicatePrompt>,
    duplicate_index: Option<usize>,
    master_password: Option<String>,
    master_salt: Option<[u8; 16]>,
    vault_path: String,
    tech_path: String,
    auth_buffer: String,
    auth_message: String,
    backup_dir_buffer: String,
    backup_message: String,
    upload_path_buffer: String,
    upload_message: String,
    show_auth_password: bool,
    status_ok: bool,
    status_message: String,
    decrypted_current: Option<(String, String)>, // (username, password)
}

impl AppState {
    fn new() -> Self {
        AppState {
            screen: AppScreen::SetupPassword,
            entries: Vec::new(),
            stored_entries: Vec::new(),
            input_buffers: [String::new(), String::new(), String::new()],
            input_field: 0,
            selected_index: 0,
            search_query: String::new(),
            search_field_active: true,
            confirm_delete: false,
            pending_delete_index: None,
            edit_prompt: None,
            edit_index: None,
            edit_auth_buffer: String::new(),
            edit_buffers: [String::new(), String::new()],
            edit_field: 0,
            duplicate_prompt: None,
            duplicate_index: None,
            master_password: None,
            master_salt: None,
            vault_path: "vault.json".to_string(),
            tech_path: "tech.json".to_string(),
            auth_buffer: String::new(),
            auth_message: String::new(),
            backup_dir_buffer: String::new(),
            backup_message: String::new(),
            upload_path_buffer: String::new(),
            upload_message: String::new(),
            show_auth_password: false,
            status_ok: true,
            status_message: "OK".to_string(),
            decrypted_current: None,
        }
    }

    fn set_status_ok(&mut self) {
        self.status_ok = true;
        self.status_message = "OK".to_string();
    }

    fn set_status_error(&mut self, message: impl Into<String>) {
        self.status_ok = false;
        self.status_message = message.into();
    }

    fn reset_input(&mut self) {
        self.input_buffers = [String::new(), String::new(), String::new()];
        self.input_field = 0;
        self.duplicate_prompt = None;
        self.duplicate_index = None;
    }

    fn add_entry(&mut self) {
        if self.input_buffers[0].is_empty() || self.master_password.is_none() {
            return;
        }

        if let Some(index) = self.find_service_index(&self.input_buffers[0]) {
            self.duplicate_index = Some(index);
            self.duplicate_prompt = Some(DuplicatePrompt::Overwrite);
            return;
        }

        self.insert_current_entry(self.input_buffers[0].clone());
    }

    fn find_service_index(&self, service: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.service.eq_ignore_ascii_case(service))
    }

    fn insert_current_entry(&mut self, service: String) {
        self.entries.push(PasswordEntry {
            service,
            username: self.input_buffers[1].clone(),
            password: self.input_buffers[2].clone(),
        });
        self.reset_input();
        self.screen = AppScreen::Menu;
        self.save_entries();
    }

    fn overwrite_duplicate_entry(&mut self) {
        if let Some(index) = self.duplicate_index {
            if let Some(entry) = self.entries.get_mut(index) {
                entry.username = self.input_buffers[1].clone();
                entry.password = self.input_buffers[2].clone();
            }
            self.reset_input();
            self.screen = AppScreen::Menu;
            self.save_entries();
        }
    }

    fn next_duplicate_service_name(&self, base: &str) -> String {
        let mut copy_number = 1;
        loop {
            let candidate = format!("{}{}", base, copy_number);
            if self.find_service_index(&candidate).is_none() {
                return candidate;
            }
            copy_number += 1;
        }
    }

    fn save_duplicate_copy(&mut self) {
        let service = self.next_duplicate_service_name(&self.input_buffers[0]);
        self.insert_current_entry(service);
    }

    fn reset_backup(&mut self) {
        self.backup_dir_buffer.clear();
        self.backup_message = "Enter destination directory for encrypted vault copy".to_string();
    }

    fn backup_vault(&mut self) {
        let destination_dir = PathBuf::from(self.backup_dir_buffer.trim());
        if self.backup_dir_buffer.trim().is_empty() {
            self.backup_message = "Destination directory is required".to_string();
            self.set_status_error("backup destination missing");
            return;
        }
        if !destination_dir.is_dir() {
            self.backup_message = "Destination is not a valid directory".to_string();
            self.set_status_error("backup directory invalid");
            return;
        }
        if fs::metadata(&self.vault_path).is_err() {
            self.backup_message = "vault.json does not exist yet".to_string();
            self.set_status_error("vault file missing");
            return;
        }

        let mut vault_destination = destination_dir.clone();
        vault_destination.push("vault.backup.json");
        let vault_result = fs::copy(&self.vault_path, &vault_destination);

        let mut tech_result = Ok(0);
        if fs::metadata(&self.tech_path).is_ok() {
            let mut tech_destination = destination_dir;
            tech_destination.push("tech.backup.json");
            tech_result = fs::copy(&self.tech_path, &tech_destination);
        }

        if vault_result.is_ok() && tech_result.is_ok() {
            self.backup_message = format!("Backup copied to {}", vault_destination.display());
            self.set_status_ok();
        } else if vault_result.is_ok() {
            self.backup_message = format!(
                "Vault backup copied to {} (tech.json missing)",
                vault_destination.display()
            );
            self.set_status_ok();
        } else {
            self.backup_message = "Could not copy vault.json".to_string();
            self.set_status_error("vault backup failed");
        }
    }

    fn reset_upload_backup(&mut self) {
        self.upload_path_buffer.clear();
        self.upload_message = "Enter encrypted backup file path".to_string();
    }

    fn upload_backup(&mut self) {
        let backup_path = PathBuf::from(self.upload_path_buffer.trim());
        if self.upload_path_buffer.trim().is_empty() {
            self.upload_message = "Backup file path is required".to_string();
            self.set_status_error("backup path missing");
            return;
        }
        if !backup_path.is_file() {
            self.upload_message = "Backup file does not exist".to_string();
            self.set_status_error("backup file missing");
            return;
        }

        let backup_dir = backup_path.parent().unwrap_or(Path::new("."));
        let tech_backup_path = backup_dir.join("tech.backup.json");
        let mut tech_restored = false;

        if tech_backup_path.is_file() {
            if fs::copy(&tech_backup_path, &self.tech_path).is_ok() {
                tech_restored = true;
            }
        }

        match fs::copy(&backup_path, &self.vault_path) {
            Ok(_) => {
                if tech_restored {
                    self.master_salt = read_tech_file(&self.tech_path).map(|tech| tech.salt);
                }
                self.entries.clear();
                self.stored_entries.clear();
                self.load_entries();
                if self.status_ok {
                    let mut message = "Encrypted backup restored into vault.json".to_string();
                    if tech_restored {
                        message.push_str(" and tech.json restored");
                    }
                    self.upload_message = message;
                } else {
                    self.upload_message =
                        "Backup copied, but it could not be decrypted with current login"
                            .to_string();
                }
            }
            Err(_) => {
                self.upload_message = "Could not copy backup into vault.json".to_string();
                self.set_status_error("backup upload failed");
            }
        }
    }

    fn reset_search(&mut self) {
        self.search_query.clear();
        self.search_field_active = true;
        self.selected_index = 0;
        self.confirm_delete = false;
        self.pending_delete_index = None;
        self.reset_edit_prompt();
    }

    fn reset_edit_prompt(&mut self) {
        self.edit_prompt = None;
        self.edit_index = None;
        self.edit_auth_buffer.clear();
        self.edit_buffers = [String::new(), String::new()];
        self.edit_field = 0;
    }

    fn filtered_entry_indices(&self) -> Vec<usize> {
        let query = self.search_query.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| query.is_empty() || entry.service.to_lowercase().contains(&query))
            .map(|(index, _)| index)
            .collect()
    }

    fn selected_entry_index(&self) -> Option<usize> {
        self.filtered_entry_indices()
            .get(self.selected_index)
            .copied()
    }

    fn clamp_selected_index(&mut self) {
        let visible_len = self.filtered_entry_indices().len();
        if visible_len == 0 {
            self.selected_index = 0;
        } else if self.selected_index >= visible_len {
            self.selected_index = visible_len - 1;
        }
    }

    fn delete_entry(&mut self, index: usize) {
        if index < self.entries.len() {
            self.entries.remove(index);
            self.decrypted_current = None;
            self.confirm_delete = false;
            self.pending_delete_index = None;
            self.clamp_selected_index();
            self.save_entries();
        }
    }

    fn start_edit_auth(&mut self) {
        if let Some(index) = self.selected_entry_index() {
            self.edit_index = Some(index);
            self.edit_auth_buffer.clear();
            self.edit_prompt = Some(EditPrompt::Auth);
        }
    }

    fn unlock_edit_prompt(&mut self) {
        if verify_tech_file(&self.tech_path, &self.edit_auth_buffer) {
            if let Some(index) = self.edit_index {
                if let Some(entry) = self.entries.get(index) {
                    self.edit_buffers = [entry.username.clone(), entry.password.clone()];
                    self.edit_field = 0;
                    self.edit_auth_buffer.clear();
                    self.edit_prompt = Some(EditPrompt::Edit);
                }
            }
        } else {
            self.edit_auth_buffer.clear();
        }
    }

    fn save_edited_entry(&mut self) {
        if let Some(index) = self.edit_index {
            if let Some(entry) = self.entries.get_mut(index) {
                entry.username = self.edit_buffers[0].clone();
                entry.password = self.edit_buffers[1].clone();
                self.save_entries();
            }
        }
        self.reset_edit_prompt();
    }

    fn initialize_security(&mut self) {
        let tech_exists = fs::metadata(&self.tech_path).is_ok();
        let vault_exists = fs::metadata(&self.vault_path).is_ok();

        if !tech_exists && vault_exists && self.vault_log_enabled() {
            self.screen = AppScreen::SecurityRisk;
            self.auth_message = "secury recovery risk".to_string();
        } else if tech_exists {
            self.screen = AppScreen::LoginPassword;
            self.auth_message = "Enter initial password".to_string();
        } else {
            self.screen = AppScreen::SetupPassword;
            self.auth_message = "Create password: 8+ chars, 1 number, 1 special symbol".to_string();
        }
    }

    fn vault_log_enabled(&self) -> bool {
        fs::read_to_string(&self.vault_path)
            .ok()
            .and_then(|json| serde_json::from_str::<VaultDiskFormat>(&json).ok())
            .map(|vault| match vault {
                VaultDiskFormat::Current(vault) => vault.log,
                VaultDiskFormat::Legacy(_) => false,
            })
            .unwrap_or(false)
    }

    fn setup_initial_password(&mut self) {
        match validate_initial_password(&self.auth_buffer) {
            Ok(()) => match create_tech_file(&self.tech_path, &self.auth_buffer) {
                Ok(()) => {
                    self.master_password = Some(self.auth_buffer.clone());
                    self.master_salt = read_tech_file(&self.tech_path).map(|tech| tech.salt);
                    self.auth_buffer.clear();
                    self.auth_message.clear();
                    self.entries.clear();
                    self.save_entries();
                    self.screen = AppScreen::Menu;
                }
                Err(_) => {
                    self.auth_message = "Could not create tech.json".to_string();
                    self.set_status_error("tech.json creation failed");
                }
            },
            Err(message) => {
                self.auth_message = message;
            }
        }
    }

    fn login_initial_password(&mut self) {
        if verify_tech_file(&self.tech_path, &self.auth_buffer) {
            self.master_password = Some(self.auth_buffer.clone());
            self.master_salt = read_tech_file(&self.tech_path).map(|tech| tech.salt);
            self.auth_buffer.clear();
            self.auth_message.clear();
            self.load_entries();
            self.screen = AppScreen::Menu;
        } else {
            self.auth_buffer.clear();
            self.auth_message = "Invalid password".to_string();
            self.set_status_error("invalid login password");
        }
    }

    fn destroy_vault_after_security_risk(&mut self) {
        self.entries.clear();
        self.stored_entries.clear();
        let vault = VaultFile {
            log: false,
            entries: Vec::new(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&vault) {
            if fs::write(&self.vault_path, json).is_err() {
                self.set_status_error("vault destroy write failed");
                return;
            }
            self.set_status_ok();
        } else {
            self.set_status_error("vault destroy serialization failed");
        }
        self.auth_buffer.clear();
        self.auth_message =
            "Passwords destroyed. Create a new initial password to continue.".to_string();
        self.screen = AppScreen::SetupPassword;
    }

    fn save_entries(&mut self) {
        if let (Some(master_pwd), Some(salt)) = (&self.master_password, self.master_salt) {
            let params = kdf::KdfParams {
                memory_kb: 8192,
                time_cost: 1,
                parallelism: 1,
            };

            let Ok(key) = kdf::derive_key(master_pwd.as_bytes(), &salt, &params) else {
                self.set_status_error("key derivation failed");
                return;
            };

            let mut stored = Vec::new();

            for entry in &self.entries {
                let Ok((username_ct, username_nonce)) =
                    cipher::encrypt(entry.username.as_bytes(), &key, entry.service.as_bytes())
                else {
                    self.set_status_error("username encryption failed");
                    return;
                };
                let Ok((password_ct, password_nonce)) =
                    cipher::encrypt(entry.password.as_bytes(), &key, entry.service.as_bytes())
                else {
                    self.set_status_error("password encryption failed");
                    return;
                };
                stored.push(StoredEntry {
                    service: entry.service.clone(),
                    username_ciphertext: username_ct,
                    username_nonce,
                    password_ciphertext: password_ct,
                    password_nonce,
                });
            }

            let vault = VaultFile {
                log: true,
                entries: stored,
            };

            match serde_json::to_string_pretty(&vault) {
                Ok(json) => {
                    if fs::write(&self.vault_path, json).is_ok() {
                        self.set_status_ok();
                    } else {
                        self.set_status_error("vault write failed");
                    }
                }
                Err(_) => {
                    self.set_status_error("vault serialization failed");
                }
            }
        }
    }

    fn load_entries(&mut self) {
        if let (Some(master_pwd), Some(salt)) = (&self.master_password, self.master_salt) {
            if let Ok(json) = fs::read_to_string(&self.vault_path) {
                let Ok(vault) = serde_json::from_str::<VaultDiskFormat>(&json) else {
                    self.set_status_error("vault json parse failed");
                    return;
                };
                self.stored_entries = match vault {
                    VaultDiskFormat::Current(vault) => vault.entries,
                    VaultDiskFormat::Legacy(entries) => entries,
                };

                let params = kdf::KdfParams {
                    memory_kb: 8192,
                    time_cost: 1,
                    parallelism: 1,
                };

                match decrypt_stored_entries(&self.stored_entries, master_pwd, &salt, &params) {
                    Ok(decrypted) => {
                        self.entries = decrypted;
                        self.set_status_ok();
                    }
                    Err(_) => {
                        let legacy_salt = [0u8; 16];
                        match decrypt_stored_entries(
                            &self.stored_entries,
                            master_pwd,
                            &legacy_salt,
                            &params,
                        ) {
                            Ok(decrypted) => {
                                self.entries = decrypted;
                                self.set_status_ok();
                                self.save_entries();
                            }
                            Err(message) => self.set_status_error(message),
                        }
                    }
                }
            }
        }
    }
}

fn auth_kdf_params() -> kdf::KdfParams {
    kdf::KdfParams {
        memory_kb: 8192,
        time_cost: 1,
        parallelism: 1,
    }
}

fn validate_initial_password(password: &str) -> std::result::Result<(), String> {
    if password.chars().count() < 8 {
        return Err("Password must have at least 8 characters".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must include at least one number".to_string());
    }
    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return Err("Password must include at least one special symbol".to_string());
    }
    Ok(())
}

fn create_tech_file(
    tech_path: &str,
    password: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let salt = kdf::generate_salt();
    let key = kdf::derive_key(password.as_bytes(), &salt, &auth_kdf_params())?;
    let (check_ciphertext, check_nonce) =
        cipher::encrypt(b"passm3nage-tech-check", &key, b"tech.json")?;
    let tech = TechFile {
        salt,
        check_ciphertext,
        check_nonce,
    };
    fs::write(tech_path, serde_json::to_string_pretty(&tech)?)?;
    Ok(())
}

fn read_tech_file(tech_path: &str) -> Option<TechFile> {
    let json = fs::read_to_string(tech_path).ok()?;
    serde_json::from_str::<TechFile>(&json).ok()
}

fn verify_tech_file(tech_path: &str, password: &str) -> bool {
    let Some(tech) = read_tech_file(tech_path) else {
        return false;
    };
    let Ok(key) = kdf::derive_key(password.as_bytes(), &tech.salt, &auth_kdf_params()) else {
        return false;
    };
    cipher::decrypt(
        &tech.check_ciphertext,
        &key,
        &tech.check_nonce,
        b"tech.json",
    )
    .map(|plaintext| plaintext == b"passm3nage-tech-check")
    .unwrap_or(false)
}

fn decrypt_stored_entries(
    stored_entries: &[StoredEntry],
    master_pwd: &str,
    salt: &[u8; 16],
    params: &kdf::KdfParams,
) -> std::result::Result<Vec<PasswordEntry>, &'static str> {
    let key = kdf::derive_key(master_pwd.as_bytes(), salt, params)
        .map_err(|_| "key derivation failed")?;
    let mut decrypted = Vec::new();

    for stored in stored_entries {
        let username_bytes = cipher::decrypt(
            &stored.username_ciphertext,
            &key,
            &stored.username_nonce,
            stored.service.as_bytes(),
        )
        .map_err(|_| "username decrypt failed")?;
        let password_bytes = cipher::decrypt(
            &stored.password_ciphertext,
            &key,
            &stored.password_nonce,
            stored.service.as_bytes(),
        )
        .map_err(|_| "password decrypt failed")?;
        let username =
            String::from_utf8(username_bytes).map_err(|_| "username utf8 decode failed")?;
        let password =
            String::from_utf8(password_bytes).map_err(|_| "password utf8 decode failed")?;
        decrypted.push(PasswordEntry {
            service: stored.service.clone(),
            username,
            password,
        });
    }

    Ok(decrypted)
}

fn print_help() {
    println!("Usage:");
    println!("passm3nage");
    println!("");
    println!("Options:");
    println!("--help");
    println!("--version");
}

fn print_version() {
    println!("PassM3nage v{}", env!("CARGO_PKG_VERSION"));
}

fn main() {
    let mut args = env::args().skip(1);
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" | "-V" => {
                print_version();
                return;
            }
            unknown => {
                eprintln!("Unknown option: {}", unknown);
                print_help();
                std::process::exit(1);
            }
        }
    }

    if let Err(err) = run() {
        eprintln!("Application error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    state.initialize_security();

    loop {
        terminal.draw(|f| match state.screen {
            AppScreen::SetupPassword => draw_auth_password(f, &state, "Create Initial Password"),
            AppScreen::LoginPassword => draw_auth_password(f, &state, "Unlock PassM3nage"),
            AppScreen::SecurityRisk => draw_security_risk(f, &state),
            AppScreen::Menu => draw_menu(f, &state),
            AppScreen::AddEntry => draw_add_entry(f, &state),
            AppScreen::BackupVault => draw_backup_vault(f, &state),
            AppScreen::UploadBackup => draw_upload_backup(f, &state),
            AppScreen::ViewEntries => draw_view_entries(f, &state),
            AppScreen::SelectEntry => draw_select_entry(f, &state),
            AppScreen::ShowPassword => draw_show_password(f, &state),
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Ignore key release events - only process key press events
                if key.kind == KeyEventKind::Press {
                    match state.screen {
                        AppScreen::SetupPassword => handle_setup_password_input(&mut state, key)?,
                        AppScreen::LoginPassword => handle_login_password_input(&mut state, key)?,
                        AppScreen::SecurityRisk => handle_security_risk_input(&mut state, key)?,
                        AppScreen::Menu => handle_menu_input(&mut state, key)?,
                        AppScreen::AddEntry => handle_add_entry_input(&mut state, key)?,
                        AppScreen::BackupVault => handle_backup_vault_input(&mut state, key)?,
                        AppScreen::UploadBackup => handle_upload_backup_input(&mut state, key)?,
                        AppScreen::ViewEntries => handle_view_entries_input(&mut state, key)?,
                        AppScreen::SelectEntry => handle_select_entry_input(&mut state, key)?,
                        AppScreen::ShowPassword => handle_show_password_input(&mut state, key)?,
                    }
                }
            }
        }
    }
}

fn draw_menu(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(size);

    let title = Paragraph::new("PassM3nage - Password Manager")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title("Main Menu"));

    let items = vec![
        ListItem::new("(A)dd new entry"),
        ListItem::new("(S)earch password"),
        ListItem::new("(B)ackup encrypted vault"),
        ListItem::new("(U)pload backup"),
        ListItem::new("(Q)uit"),
    ];
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Options"))
        .style(Style::default().fg(Color::White));

    let status_label = if state.status_ok { "OK" } else { "ERROR" };
    let status_color = if state.status_ok {
        Color::Green
    } else {
        Color::Red
    };
    let status = Paragraph::new(format!(
        "Passwords saved: {} | Program status: {} | {}",
        state.entries.len(),
        status_label,
        state.status_message
    ))
    .style(Style::default().fg(status_color))
    .block(Block::default().borders(Borders::ALL).title("Status"));

    f.render_widget(title, chunks[0]);
    f.render_widget(list, chunks[1]);
    f.render_widget(status, chunks[2]);
}

fn draw_auth_password(f: &mut ratatui::Frame, state: &AppState, title: &str) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    let password_text = if state.show_auth_password {
        state.auth_buffer.clone()
    } else {
        "*".repeat(state.auth_buffer.chars().count())
    };
    let password = Paragraph::new(password_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Password"));
    let help = Paragraph::new(format!(
        "{}\nTab: show/hide password | Enter: confirm | Backspace: delete | Esc: exit",
        state.auth_message
    ))
    .style(Style::default().fg(Color::Gray))
    .block(Block::default().borders(Borders::ALL).title("Rules"));

    f.render_widget(title, chunks[0]);
    f.render_widget(password, chunks[1]);
    f.render_widget(help, chunks[2]);
}

fn draw_security_risk(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let area = centered_rect(64, 11, size);
    let warning = Paragraph::new(format!(
        "{}\n\nvault.json has log=true but tech.json is missing.\nSomeone may be trying to bypass the initial password.\n\n1: exit\n2: destroy all saved passwords",
        state.auth_message
    ))
    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    .block(Block::default().borders(Borders::ALL).title("Security Alert"));

    f.render_widget(Clear, area);
    f.render_widget(warning, area);
}

fn draw_add_entry(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new("PassM3nage - Add New Entry")
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));

    let field_names = ["Service Name", "Username", "Password"];

    let service_input = Paragraph::new(state.input_buffers[0].as_str())
        .style(if state.input_field == 0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        })
        .block(Block::default().borders(Borders::ALL).title(format!(
            "{} {}",
            field_names[0],
            if state.input_field == 0 { "✎" } else { "" }
        )));

    let username_input = Paragraph::new(state.input_buffers[1].as_str())
        .style(if state.input_field == 1 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        })
        .block(Block::default().borders(Borders::ALL).title(format!(
            "{} {}",
            field_names[1],
            if state.input_field == 1 { "✎" } else { "" }
        )));

    let password_input = Paragraph::new(state.input_buffers[2].as_str())
        .style(if state.input_field == 2 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        })
        .block(Block::default().borders(Borders::ALL).title(format!(
            "{} {}",
            field_names[2],
            if state.input_field == 2 { "✎" } else { "" }
        )));

    let help = Paragraph::new("Tab: next field | Enter: confirm | Esc: cancel")
        .style(Style::default().fg(Color::Gray));

    f.render_widget(title, chunks[0]);
    f.render_widget(service_input, chunks[1]);
    f.render_widget(username_input, chunks[2]);
    f.render_widget(password_input, chunks[3]);
    f.render_widget(help, chunks[4]);

    if let Some(prompt) = state.duplicate_prompt {
        let area = centered_rect(64, 9, size);
        let service = state.input_buffers[0].as_str();
        let text = match prompt {
            DuplicatePrompt::Overwrite => format!(
                "Service '{}' already exists.\n\nOverwrite existing data?\n\nY: overwrite    N: no",
                service
            ),
            DuplicatePrompt::SaveCopy => {
                let copy_name = state.next_duplicate_service_name(service);
                format!(
                    "Keep the existing service unchanged?\n\nSave this entry as '{}'?\n\nY: save copy    N/Esc: cancel",
                    copy_name
                )
            }
        };
        let popup = Paragraph::new(text)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Duplicate service"),
            );
        f.render_widget(Clear, area);
        f.render_widget(popup, area);
    }
}

fn draw_backup_vault(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new("PassM3nage - Backup Encrypted Vault")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    let dir = Paragraph::new(state.backup_dir_buffer.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Destination directory"),
        );
    let help = Paragraph::new(format!(
        "{}\nEnter: copy vault.backup.json and tech.backup.json | Esc: menu",
        state.backup_message
    ))
    .style(Style::default().fg(Color::Gray))
    .block(Block::default().borders(Borders::ALL).title("Info"));

    f.render_widget(title, chunks[0]);
    f.render_widget(dir, chunks[1]);
    f.render_widget(help, chunks[2]);
}

fn draw_upload_backup(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new("PassM3nage - Upload Backup")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    let path = Paragraph::new(state.upload_path_buffer.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Vault backup file path"),
        );
    let help = Paragraph::new(format!(
        "{}\nEnter: restore vault.backup.json (tech.backup.json will also be restored if present) | Esc: menu",
        state.upload_message
    ))
    .style(Style::default().fg(Color::Gray))
    .block(Block::default().borders(Borders::ALL).title("Info"));

    f.render_widget(title, chunks[0]);
    f.render_widget(path, chunks[1]);
    f.render_widget(help, chunks[2]);
}

fn draw_view_entries(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(size);

    let title = Paragraph::new("PassM3nage - Saved Entries")
        .style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));

    let entries_text = if state.entries.is_empty() {
        "No entries yet. Add one from the menu!".to_string()
    } else {
        state
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                format!(
                    "{}. {} | User: {} | Pass: {}",
                    i + 1,
                    e.service,
                    e.username,
                    "*".repeat(e.password.len())
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let entries = Paragraph::new(entries_text)
        .block(Block::default().borders(Borders::ALL).title("Your Entries"))
        .style(Style::default().fg(Color::White));

    f.render_widget(title, chunks[0]);
    f.render_widget(entries, chunks[1]);
}

fn draw_select_entry(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(size);

    let title = Paragraph::new("PassM3nage - Search Password")
        .style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));

    let search_style = if state.search_field_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let search = Paragraph::new(state.search_query.as_str())
        .style(search_style)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Search service"),
        );

    let filtered_indices = state.filtered_entry_indices();
    let items = if state.entries.is_empty() {
        vec![ListItem::new("No entries saved")]
    } else if filtered_indices.is_empty() {
        vec![ListItem::new("No matching services")]
    } else {
        filtered_indices
            .iter()
            .enumerate()
            .map(|(visible_index, entry_index)| {
                let entry = &state.entries[*entry_index];
                let marker = if visible_index == state.selected_index {
                    "> "
                } else {
                    "  "
                };
                ListItem::new(format!("{}{}", marker, entry.service))
            })
            .collect()
    };

    let entries = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Results"))
        .style(Style::default().fg(Color::White));

    let help = Paragraph::new(
        "Type to search | Tab: results/search | W/S: choose | Enter: show | E: edit | C: delete | Esc: menu",
    )
    .style(Style::default().fg(Color::Gray));

    f.render_widget(title, chunks[0]);
    f.render_widget(search, chunks[1]);
    f.render_widget(entries, chunks[2]);
    f.render_widget(help, chunks[3]);

    if state.confirm_delete {
        let area = centered_rect(56, 7, size);
        let service = state
            .pending_delete_index
            .and_then(|index| state.entries.get(index))
            .map(|entry| entry.service.as_str())
            .unwrap_or("selected entry");
        let popup = Paragraph::new(format!(
            "Delete '{}'?\n\nY: confirm    N/Esc: cancel",
            service
        ))
        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Confirm delete"),
        );
        f.render_widget(Clear, area);
        f.render_widget(popup, area);
    }

    if let Some(prompt) = state.edit_prompt {
        let area = centered_rect(64, 11, size);
        let popup = match prompt {
            EditPrompt::Auth => {
                let masked = "*".repeat(state.edit_auth_buffer.chars().count());
                Paragraph::new(format!(
                    "Re-enter login password to edit.\n\nPassword: {}\n\nEnter: confirm    Esc: cancel",
                    masked
                ))
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Edit locked"))
            }
            EditPrompt::Edit => {
                let username_marker = if state.edit_field == 0 { "> " } else { "  " };
                let password_marker = if state.edit_field == 1 { "> " } else { "  " };
                Paragraph::new(format!(
                    "{}Username: {}\n{}Password: {}\n\nTab: field | Enter: save | Esc: cancel",
                    username_marker, state.edit_buffers[0], password_marker, state.edit_buffers[1]
                ))
                .style(
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Edit credentials"),
                )
            }
        };
        f.render_widget(Clear, area);
        f.render_widget(popup, area);
    }
}

fn draw_show_password(f: &mut ratatui::Frame, state: &AppState) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new("PassM3nage - Password")
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));

    let service = state
        .selected_entry_index()
        .and_then(|index| state.entries.get(index))
        .map(|entry| entry.service.as_str())
        .unwrap_or("No entry selected");
    let (username, password) = state
        .decrypted_current
        .as_ref()
        .map(|(username, password)| (username.as_str(), password.as_str()))
        .unwrap_or(("", ""));

    let username = Paragraph::new(username).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("{} username", service)),
    );
    let password = Paragraph::new(password)
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("Password"));
    let help =
        Paragraph::new("Esc: back to entries | Q: menu").style(Style::default().fg(Color::Gray));

    f.render_widget(title, chunks[0]);
    f.render_widget(username, chunks[1]);
    f.render_widget(password, chunks[2]);
    f.render_widget(help, chunks[3]);
}

fn centered_rect(width: u16, height: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height.min(area.height)),
            Constraint::Min(0),
        ])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(width.min(area.width)),
            Constraint::Min(0),
        ])
        .split(vertical[1]);

    horizontal[1]
}

fn handle_menu_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Char('a') | KeyCode::Char('A') => {
            state.screen = AppScreen::AddEntry;
            state.reset_input();
        }
        KeyCode::Char('b') | KeyCode::Char('B') => {
            state.reset_backup();
            state.screen = AppScreen::BackupVault;
        }
        KeyCode::Char('u') | KeyCode::Char('U') => {
            state.reset_upload_backup();
            state.screen = AppScreen::UploadBackup;
        }
        KeyCode::Char('v') | KeyCode::Char('V') => {
            state.screen = AppScreen::ViewEntries;
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            state.reset_search();
            state.screen = AppScreen::SelectEntry;
        }
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
            disable_raw_mode()?;
            execute!(io::stdout(), LeaveAlternateScreen)?;
            std::process::exit(0);
        }
        _ => {}
    }
    Ok(())
}

fn handle_backup_vault_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Char(c) => {
            state.backup_dir_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.backup_dir_buffer.pop();
        }
        KeyCode::Enter => {
            state.backup_vault();
        }
        KeyCode::Esc => {
            state.backup_dir_buffer.clear();
            state.screen = AppScreen::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_upload_backup_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Char(c) => {
            state.upload_path_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.upload_path_buffer.pop();
        }
        KeyCode::Enter => {
            state.upload_backup();
        }
        KeyCode::Esc => {
            state.upload_path_buffer.clear();
            state.screen = AppScreen::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_setup_password_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Tab => {
            state.show_auth_password = !state.show_auth_password;
        }
        KeyCode::Char(c) => state.auth_buffer.push(c),
        KeyCode::Backspace => {
            state.auth_buffer.pop();
        }
        KeyCode::Enter => state.setup_initial_password(),
        KeyCode::Esc => {
            disable_raw_mode()?;
            execute!(io::stdout(), LeaveAlternateScreen)?;
            std::process::exit(0);
        }
        _ => {}
    }
    Ok(())
}

fn handle_login_password_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Tab => {
            state.show_auth_password = !state.show_auth_password;
        }
        KeyCode::Char(c) => state.auth_buffer.push(c),
        KeyCode::Backspace => {
            state.auth_buffer.pop();
        }
        KeyCode::Enter => state.login_initial_password(),
        KeyCode::Esc => {
            disable_raw_mode()?;
            execute!(io::stdout(), LeaveAlternateScreen)?;
            std::process::exit(0);
        }
        _ => {}
    }
    Ok(())
}

fn handle_security_risk_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Char('1') | KeyCode::Esc => {
            disable_raw_mode()?;
            execute!(io::stdout(), LeaveAlternateScreen)?;
            std::process::exit(0);
        }
        KeyCode::Char('2') => state.destroy_vault_after_security_risk(),
        _ => {}
    }
    Ok(())
}

fn handle_add_entry_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if let Some(prompt) = state.duplicate_prompt {
        match (prompt, key.code) {
            (DuplicatePrompt::Overwrite, KeyCode::Char('y') | KeyCode::Char('Y')) => {
                state.overwrite_duplicate_entry();
            }
            (DuplicatePrompt::Overwrite, KeyCode::Char('n') | KeyCode::Char('N')) => {
                state.duplicate_prompt = Some(DuplicatePrompt::SaveCopy);
            }
            (DuplicatePrompt::SaveCopy, KeyCode::Char('y') | KeyCode::Char('Y')) => {
                state.save_duplicate_copy();
            }
            (DuplicatePrompt::SaveCopy, KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc) => {
                state.duplicate_prompt = None;
                state.duplicate_index = None;
            }
            _ => {}
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Char(c) => {
            state.input_buffers[state.input_field].push(c);
        }
        KeyCode::Backspace => {
            state.input_buffers[state.input_field].pop();
        }
        KeyCode::Tab => {
            state.input_field = (state.input_field + 1) % 3;
        }
        KeyCode::Enter => {
            if state.input_field == 2 {
                // Last field - save entry
                state.add_entry();
            } else {
                // Move to next field
                state.input_field += 1;
            }
        }
        KeyCode::Esc => {
            state.reset_input();
            state.screen = AppScreen::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_view_entries_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc | KeyCode::Backspace => {
            state.screen = AppScreen::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_select_entry_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if let Some(prompt) = state.edit_prompt {
        match prompt {
            EditPrompt::Auth => match key.code {
                KeyCode::Char(c) => state.edit_auth_buffer.push(c),
                KeyCode::Backspace => {
                    state.edit_auth_buffer.pop();
                }
                KeyCode::Enter => state.unlock_edit_prompt(),
                KeyCode::Esc => state.reset_edit_prompt(),
                _ => {}
            },
            EditPrompt::Edit => match key.code {
                KeyCode::Char(c) => state.edit_buffers[state.edit_field].push(c),
                KeyCode::Backspace => {
                    state.edit_buffers[state.edit_field].pop();
                }
                KeyCode::Tab => {
                    state.edit_field = (state.edit_field + 1) % 2;
                }
                KeyCode::Enter => state.save_edited_entry(),
                KeyCode::Esc => state.reset_edit_prompt(),
                _ => {}
            },
        }
        return Ok(());
    }

    if state.confirm_delete {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some(index) = state.pending_delete_index {
                    state.delete_entry(index);
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Backspace => {
                state.confirm_delete = false;
                state.pending_delete_index = None;
            }
            _ => {}
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Tab => {
            state.search_field_active = !state.search_field_active;
        }
        KeyCode::Backspace if state.search_field_active => {
            state.search_query.pop();
            state.clamp_selected_index();
        }
        KeyCode::Char(c) if state.search_field_active => {
            state.search_query.push(c);
            state.clamp_selected_index();
        }
        KeyCode::Char('w') | KeyCode::Char('W') => {
            if state.selected_index > 0 {
                state.selected_index -= 1;
            }
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            if state.selected_index + 1 < state.filtered_entry_indices().len() {
                state.selected_index += 1;
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            if let Some(index) = state.selected_entry_index() {
                state.confirm_delete = true;
                state.pending_delete_index = Some(index);
            }
        }
        KeyCode::Char('e') | KeyCode::Char('E') => {
            state.start_edit_auth();
        }
        KeyCode::Enter => {
            if state.search_field_active {
                state.search_field_active = false;
            } else if let Some(entry) = state
                .selected_entry_index()
                .and_then(|index| state.entries.get(index))
            {
                state.decrypted_current = Some((entry.username.clone(), entry.password.clone()));
                state.screen = AppScreen::ShowPassword;
            }
        }
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
            state.confirm_delete = false;
            state.pending_delete_index = None;
            state.screen = AppScreen::Menu;
        }
        KeyCode::Backspace => {
            state.screen = AppScreen::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_show_password_input(
    state: &mut AppState,
    key: KeyEvent,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match key.code {
        KeyCode::Esc | KeyCode::Backspace => {
            state.decrypted_current = None;
            state.screen = AppScreen::SelectEntry;
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            state.decrypted_current = None;
            state.screen = AppScreen::Menu;
        }
        _ => {}
    }
    Ok(())
}
