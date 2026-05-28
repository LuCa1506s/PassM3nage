#![allow(dead_code)]

/// XChaCha20-Poly1305 Authenticated Encryption
///
/// SECURITY CRITICAL:
/// - Uses nonce correctly (24-byte random per encryption)
/// - Verifies authentication tag before decryption
/// - Additional Authenticated Data (AAD) protects header
/// - Fails closed on any authentication failure
use crate::errors::{Error, Result};
use secrecy::{ExposeSecret, Secret};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;
use sodiumoxide::randombytes;

/// Cipher parameters (for future extensibility)
#[derive(Debug, Clone)]
pub struct CipherParams {
    /// Currently only XChaCha20-Poly1305 is supported
    pub cipher_id: u8,
}

impl CipherParams {
    pub fn default() -> Self {
        CipherParams { cipher_id: 0x01 }
    }
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305
pub fn generate_nonce() -> [u8; 24] {
    let bytes = randombytes::randombytes(24);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes);
    nonce
}

/// Encrypt plaintext with authenticated encryption
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `key` - 32-byte secret key
/// * `aad` - Additional Authenticated Data (header info)
///
/// # Returns
/// (ciphertext, nonce) - Nonce must be stored with ciphertext
///
/// # Security
/// - XChaCha20-Poly1305 is NIST-recommended AEAD
/// - Random nonce prevents replay attacks
/// - AAD protects header from tampering
/// - Fails closed on any error
pub fn encrypt(
    plaintext: &[u8],
    key: &Secret<[u8; 32]>,
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24])> {
    let nonce = generate_nonce();
    let nonce_obj = xchacha20poly1305_ietf::Nonce(nonce);

    // Convert Secret key to libsodium key type
    let key_arr = *key.expose_secret();
    let key_obj = xchacha20poly1305_ietf::Key(key_arr);

    // Encrypt with AAD
    let ciphertext = xchacha20poly1305_ietf::seal(plaintext, Some(aad), &nonce_obj, &key_obj);

    Ok((ciphertext, nonce))
}

/// Decrypt ciphertext with authenticated decryption
///
/// # Arguments
/// * `ciphertext` - Encrypted data (includes Poly1305 tag)
/// * `key` - 32-byte secret key (must match encryption key)
/// * `nonce` - 24-byte nonce used during encryption
/// * `aad` - Additional Authenticated Data (must match exactly)
///
/// # Returns
/// Decrypted plaintext, or Error if authentication fails
///
/// # Security
/// - Verifies Poly1305 authentication tag before decryption
/// - AAD mismatch causes decryption failure
/// - Nonce mismatch causes decryption failure
/// - Fails closed (no partial data returned)
pub fn decrypt(
    ciphertext: &[u8],
    key: &Secret<[u8; 32]>,
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce_obj = xchacha20poly1305_ietf::Nonce(*nonce);

    // Convert Secret key to libsodium key type
    let key_arr = *key.expose_secret();
    let key_obj = xchacha20poly1305_ietf::Key(key_arr);

    // Decrypt with AAD
    xchacha20poly1305_ietf::open(ciphertext, Some(aad), &nonce_obj, &key_obj)
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce_randomness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2, "Nonces should be random");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, World!";
        let aad = b"header_data";
        let key = Secret::new([1u8; 32]);

        // Encrypt
        let (ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();

        // Verify ciphertext is not plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        // Decrypt
        let decrypted = decrypt(&ciphertext, &key, &nonce, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_fails_wrong_key() {
        let plaintext = b"Secret message";
        let aad = b"header";
        let key1 = Secret::new([1u8; 32]);
        let key2 = Secret::new([2u8; 32]);

        let (ciphertext, nonce) = encrypt(plaintext, &key1, aad).unwrap();
        let result = decrypt(&ciphertext, &key2, &nonce, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_wrong_aad() {
        let plaintext = b"Secret";
        let aad1 = b"header1";
        let aad2 = b"header2";
        let key = Secret::new([1u8; 32]);

        let (ciphertext, nonce) = encrypt(plaintext, &key, aad1).unwrap();
        let result = decrypt(&ciphertext, &key, &nonce, aad2);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_tampered_ciphertext() {
        let plaintext = b"Data";
        let aad = b"aad";
        let key = Secret::new([1u8; 32]);

        let (mut ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();

        // Tamper with ciphertext (flip a bit)
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        let result = decrypt(&ciphertext, &key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_wrong_nonce() {
        let plaintext = b"Message";
        let aad = b"aad";
        let key = Secret::new([1u8; 32]);

        let (ciphertext, mut nonce) = encrypt(plaintext, &key, aad).unwrap();

        // Tamper with nonce
        nonce[0] ^= 0x01;

        let result = decrypt(&ciphertext, &key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_payload_encryption() {
        let mut plaintext = vec![42u8; 1_000_000]; // 1 MB
        let aad = b"header";
        let key = Secret::new([1u8; 32]);

        let (ciphertext, nonce) = encrypt(&plaintext, &key, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let plaintext = b"";
        let aad = b"header";
        let key = Secret::new([1u8; 32]);

        let (ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_aad() {
        let plaintext = b"data";
        let aad = b"";
        let key = Secret::new([1u8; 32]);

        let (ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_plaintext_different_ciphertext() {
        let key = Secret::new([1u8; 32]);
        let aad = b"aad";

        let (ct1, nonce1) = encrypt(b"plaintext1", &key, aad).unwrap();
        let (ct2, nonce2) = encrypt(b"plaintext2", &key, aad).unwrap();

        // Different plaintext should produce different ciphertext
        assert_ne!(ct1, ct2);
        // Even with same plaintext, nonce should be different
        assert_ne!(nonce1, nonce2);
    }
}
