//! The `.lb` file format.
//!
//! Layout:
//!
//! Offset  Size   Field
//! 0       4      Magic bytes: b"LBOX"
//! 4       1      Version (currently 1)
//! 5       16     Salt (for Argon2)
//! 21      12     Nonce (for AES-256-GCM)
//! 33      N      Ciphertext (the GCM authentication tag is the last 16
//!                 bytes of this region — aes-gcm appends it automatically)
//! ```

use anyhow::{bail, Result};

pub const MAGIC: &[u8; 4] = b"LBOX";
pub const VERSION: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Header fields extracted from an `.lb` file, plus a reference to the
/// remaining ciphertext bytes.
pub struct LbFile<'a> {
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: &'a [u8],
}

/// Serializes a complete `.lb` file: header + ciphertext.
pub fn write(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Parses raw bytes read from disk into a `LbFile`, validating the magic
/// bytes, version, and minimum length before handing back slices into the
/// original buffer (no copying of the ciphertext).
pub fn parse(data: &[u8]) -> Result<LbFile<'_>> {
    const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;

    if data.len() < HEADER_LEN {
        bail!("file is too small to be a valid .lb file");
    }

    if &data[0..4] != MAGIC {
        bail!("not a valid .lb file (magic bytes mismatch)");
    }

    let version = data[4];
    if version != VERSION {
        bail!("unsupported .lb file version: {version}");
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[5..5 + SALT_LEN]);

    let nonce_start = 5 + SALT_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[nonce_start..nonce_start + NONCE_LEN]);

    let ciphertext_start = nonce_start + NONCE_LEN;
    let ciphertext = &data[ciphertext_start..];

    if ciphertext.is_empty() {
        bail!("file has no ciphertext payload");
    }

    Ok(LbFile {
        version,
        salt,
        nonce,
        ciphertext,
    })
}