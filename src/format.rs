//! The `.lb` file format.
//!
//! ```text
//! Offset  Size   Field
//! 0       4      Magic bytes: b"LBOX"
//! 4       1      Version (currently 1)
//! 5       1      Payload kind: 0 = single file, 1 = directory archive
//! 6       16     Salt (Argon2)
//! 22      12     Nonce (AES-256-GCM)
//! 34      N      Ciphertext (GCM auth tag is the last 16 bytes, appended
//!                automatically by the aes-gcm crate)
//! ```

use anyhow::{bail, Result};

pub const MAGIC: &[u8; 4] = b"LBOX";
pub const VERSION: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Whether the encrypted payload is a single file or a directory archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    SingleFile = 0,
    Directory  = 1,
}

impl PayloadKind {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::SingleFile),
            1 => Ok(Self::Directory),
            _ => bail!("unknown payload kind byte: {b}"),
        }
    }
}

/// A parsed `.lb` file header plus a borrow of the ciphertext bytes.
pub struct LbFile<'a> {
    pub version:  u8,
    pub kind:     PayloadKind,
    pub salt:     [u8; SALT_LEN],
    pub nonce:    [u8; NONCE_LEN],
    pub ciphertext: &'a [u8],
}

/// Serialise a complete `.lb` file: header + ciphertext.
pub fn write(
    kind: PayloadKind,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(kind as u8);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Parse raw bytes from disk, validating magic, version, and minimum length.
pub fn parse(data: &[u8]) -> Result<LbFile<'_>> {
    // 4 magic + 1 version + 1 kind + 16 salt + 12 nonce
    const HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN;

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

    let kind = PayloadKind::from_byte(data[5])?;

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[6..6 + SALT_LEN]);

    let nonce_start = 6 + SALT_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[nonce_start..nonce_start + NONCE_LEN]);

    let ciphertext_start = nonce_start + NONCE_LEN;
    let ciphertext = &data[ciphertext_start..];

    if ciphertext.is_empty() {
        bail!("file has no ciphertext payload");
    }

    Ok(LbFile { version, kind, salt, nonce, ciphertext })
}