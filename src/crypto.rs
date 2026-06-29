//! Cryptographic primitives: Argon2 key derivation and AES-256-GCM
//! encryption/decryption. This module knows nothing about file formats or
//! the filesystem — it only deals with bytes in, bytes out.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Argon2, Params};
use rand::RngCore;
use zeroize::Zeroize;

use crate::format::{NONCE_LEN, SALT_LEN};

/// Argon2 parameters. These are deliberately stronger than the library
/// defaults (~19 MiB) because this tool protects user files, not just web
/// login sessions. Tune these down if encryption feels too slow on your
/// target hardware.
///
/// - memory: 64 MiB
/// - iterations: 3
/// - parallelism: 4 lanes
fn argon2_params() -> Params {
    Params::new(64 * 1024, 3, 4, Some(32)).expect("valid argon2 params")
}

/// A 32-byte AES-256 key derived from a password + salt. Wrapped in a type
/// so we can guarantee it gets zeroed out of memory when dropped, rather
/// than lingering in a stack frame somewhere.
pub struct DerivedKey([u8; 32]);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Generates a random salt for Argon2.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Generates a random nonce for AES-256-GCM. Must never be reused with the
/// same key — generating it fresh per-encryption from a CSPRNG is correct.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Derives a 32-byte AES key from a password and salt using Argon2id.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<DerivedKey> {
    let mut key_bytes = [0u8; 32];

    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params(),
    )
    .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
    .map_err(|error| anyhow!("failed to derive encryption key: {error}"))?;

    Ok(DerivedKey(key_bytes))
}

/// Encrypts `plaintext` under `key` and `nonce`. The returned `Vec<u8>`
/// includes the GCM authentication tag appended at the end (this is
/// handled automatically by the `aes-gcm` crate).
pub fn encrypt(key: &DerivedKey, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|error| anyhow!("failed to initialize cipher: {error}"))?;

    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|error| anyhow!("encryption failed: {error}"))
}

/// Decrypts `ciphertext` (which includes the trailing GCM tag) under `key`
/// and `nonce`. Returns an error if the password was wrong or the data was
/// tampered with — GCM's tag check makes these indistinguishable, which is
/// intentional (it stops an attacker from learning anything from *why*
/// decryption failed).
pub fn decrypt(key: &DerivedKey, nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|error| anyhow!("failed to initialize cipher: {error}"))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("decryption failed: wrong password or corrupted/tampered file"))
}