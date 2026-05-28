#![allow(dead_code)]

/// Vault binary format specification and serialization
///
/// SECURITY CRITICAL:
/// - Magic bytes validate file type
/// - Version prevents incompatibility
/// - Header is authenticated (AAD)
/// - Payload is encrypted and authenticated
use crate::errors::{Error, Result};

/// Magic bytes identifying PassM3nage vault
const MAGIC: &[u8; 8] = b"PASSM3NE";

/// Current vault format version
const VERSION: u16 = 1;

/// Cipher ID for XChaCha20-Poly1305
const CIPHER_XC20P1305: u8 = 0x01;

/// Vault header (unencrypted but authenticated)
#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub cipher_id: u8,
    pub kdf_id: u8,
    pub argon_memory: u32,
    pub argon_time: u32,
    pub argon_lanes: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub payload_length: u32,
}

impl VaultHeader {
    /// Create new vault header with given parameters
    pub fn new(
        argon_memory: u32,
        argon_time: u32,
        argon_lanes: u32,
        salt: [u8; 16],
        nonce: [u8; 24],
        payload_length: u32,
    ) -> Result<Self> {
        let header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            cipher_id: CIPHER_XC20P1305,
            kdf_id: 0x01, // Argon2id
            argon_memory,
            argon_time,
            argon_lanes,
            salt,
            nonce,
            payload_length,
        };

        header.validate()?;
        Ok(header)
    }

    /// Validate header integrity
    pub fn validate(&self) -> Result<()> {
        // Check magic bytes
        if self.magic != *MAGIC {
            return Err(Error::InvalidMagic);
        }

        // Check version
        if self.version != VERSION {
            return Err(Error::UnsupportedVersion);
        }

        // Check cipher ID
        if self.cipher_id != CIPHER_XC20P1305 {
            return Err(Error::InvalidArgument("Unsupported cipher".to_string()));
        }

        // Validate KDF ID
        if self.kdf_id != 0x01 {
            return Err(Error::InvalidArgument("Unsupported KDF".to_string()));
        }

        // Validate Argon2id parameters
        if self.argon_memory < 8192 {
            return Err(Error::InvalidArgument(
                "Argon2id memory too low".to_string(),
            ));
        }
        if self.argon_time < 1 {
            return Err(Error::InvalidArgument(
                "Argon2id time cost too low".to_string(),
            ));
        }
        if self.argon_lanes < 1 {
            return Err(Error::InvalidArgument("Argon2id lanes too low".to_string()));
        }

        // Validate payload length
        if self.payload_length > 100 * 1024 * 1024 {
            return Err(Error::PayloadTooLarge);
        }

        Ok(())
    }

    /// Serialize header to bytes (for AAD and disk storage)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic (8 bytes)
        buf.extend_from_slice(&self.magic);

        // Version (2 bytes, little-endian)
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Cipher ID (1 byte)
        buf.push(self.cipher_id);

        // KDF ID (1 byte)
        buf.push(self.kdf_id);

        // Argon2id parameters (12 bytes)
        buf.extend_from_slice(&self.argon_memory.to_le_bytes());
        buf.extend_from_slice(&self.argon_time.to_le_bytes());
        buf.extend_from_slice(&self.argon_lanes.to_le_bytes());

        // Salt (16 bytes)
        buf.extend_from_slice(&self.salt);

        // Nonce (24 bytes)
        buf.extend_from_slice(&self.nonce);

        // Payload length (4 bytes)
        buf.extend_from_slice(&self.payload_length.to_le_bytes());

        buf
    }

    /// Deserialize header from bytes
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize)> {
        // Minimum header size: 8 + 2 + 1 + 1 + 12 + 16 + 24 + 4 = 68 bytes
        const HEADER_SIZE: usize = 68;

        if data.len() < HEADER_SIZE {
            return Err(Error::CorruptedHeader);
        }

        let mut offset = 0;

        // Magic (8 bytes)
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;

        // Version (2 bytes)
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Cipher ID (1 byte)
        let cipher_id = data[offset];
        offset += 1;

        // KDF ID (1 byte)
        let kdf_id = data[offset];
        offset += 1;

        // Argon2id parameters (12 bytes)
        let argon_memory = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let argon_time = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let argon_lanes = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // Salt (16 bytes)
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        // Nonce (24 bytes)
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[offset..offset + 24]);
        offset += 24;

        // Payload length (4 bytes)
        let payload_length = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let header = VaultHeader {
            magic,
            version,
            cipher_id,
            kdf_id,
            argon_memory,
            argon_time,
            argon_lanes,
            salt,
            nonce,
            payload_length,
        };

        header.validate()?;

        Ok((header, HEADER_SIZE))
    }
}

/// Compute Additional Authenticated Data from header
pub fn compute_aad(header: &VaultHeader) -> Vec<u8> {
    header.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialize_deserialize() {
        let header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            cipher_id: CIPHER_XC20P1305,
            kdf_id: 0x01,
            argon_memory: 65536,
            argon_time: 3,
            argon_lanes: 4,
            salt: [1u8; 16],
            nonce: [2u8; 24],
            payload_length: 1000,
        };

        let serialized = header.serialize();
        let (deserialized, size) = VaultHeader::deserialize(&serialized).unwrap();

        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.argon_memory, deserialized.argon_memory);
        assert_eq!(header.argon_time, deserialized.argon_time);
        assert_eq!(header.argon_lanes, deserialized.argon_lanes);
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.nonce, deserialized.nonce);
        assert_eq!(header.payload_length, deserialized.payload_length);
        assert_eq!(size, 68);
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut data = vec![0u8; 68];
        data[0] = 0xFF; // Invalid magic
        let result = VaultHeader::deserialize(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_version() {
        let mut header = VaultHeader {
            magic: *MAGIC,
            version: 999, // Invalid
            cipher_id: CIPHER_XC20P1305,
            kdf_id: 0x01,
            argon_memory: 65536,
            argon_time: 3,
            argon_lanes: 4,
            salt: [0u8; 16],
            nonce: [0u8; 24],
            payload_length: 100,
        };

        assert!(header.validate().is_err());
    }

    #[test]
    fn test_header_size() {
        let header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            cipher_id: CIPHER_XC20P1305,
            kdf_id: 0x01,
            argon_memory: 65536,
            argon_time: 3,
            argon_lanes: 4,
            salt: [0u8; 16],
            nonce: [0u8; 24],
            payload_length: 0,
        };

        let serialized = header.serialize();
        assert_eq!(serialized.len(), 68);
    }

    #[test]
    fn test_truncated_header() {
        let data = vec![0u8; 50]; // Too short
        let result = VaultHeader::deserialize(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_argon_memory_too_low() {
        let header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            cipher_id: CIPHER_XC20P1305,
            kdf_id: 0x01,
            argon_memory: 1024, // Too low
            argon_time: 3,
            argon_lanes: 4,
            salt: [0u8; 16],
            nonce: [0u8; 24],
            payload_length: 100,
        };

        assert!(header.validate().is_err());
    }

    #[test]
    fn test_payload_length_too_large() {
        let header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            cipher_id: CIPHER_XC20P1305,
            kdf_id: 0x01,
            argon_memory: 65536,
            argon_time: 3,
            argon_lanes: 4,
            salt: [0u8; 16],
            nonce: [0u8; 24],
            payload_length: u32::MAX,
        };

        assert!(header.validate().is_err());
    }
}
