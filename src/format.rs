//! The `.lb` file format — version 2.
//!
//! ```text
//! Offset  Size    Field
//! 0       4       Magic bytes: b"LBOX"
//! 4       1       Version (currently 2)
//! 5       1       Payload kind: 0 = single file, 1 = directory archive
//! 6       8       Created-at timestamp (Unix seconds, u64 little-endian)
//! 14      8       Original plaintext size in bytes (u64 little-endian)
//! 22      1       Original name length (u8, max 255)
//! 23      N       Original name (UTF-8, no null terminator)
//! 23+N    16      Salt  (Argon2)
//! 39+N    12      Nonce (AES-256-GCM)
//! 51+N    M+16    Ciphertext  (GCM auth tag is the last 16 bytes)
//! ```

use anyhow::{bail, Result};

pub const MAGIC:   &[u8; 4] = b"LBOX";
pub const VERSION: u8       = 2;

pub const SALT_LEN:  usize = 16;
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

    pub fn label(&self) -> &'static str {
        match self {
            Self::SingleFile => "Single file",
            Self::Directory  => "Directory",
        }
    }
}

/// Metadata stored in the header — everything `lb info` prints.
pub struct Header {
    pub version:       u8,
    pub kind:          PayloadKind,
    pub created_at:    u64,   // Unix timestamp
    pub plaintext_size: u64,  // bytes before encryption
    pub original_name: String,
    pub salt:          [u8; SALT_LEN],
    pub nonce:         [u8; NONCE_LEN],
}

/// A fully parsed `.lb` file: header + borrow of the ciphertext bytes.
pub struct LbFile<'a> {
    pub header:     Header,
    pub ciphertext: &'a [u8],
}

/// Serialise a complete `.lb` file.
pub fn write(
    kind:           PayloadKind,
    original_name:  &str,
    plaintext_size: u64,
    salt:           &[u8; SALT_LEN],
    nonce:          &[u8; NONCE_LEN],
    ciphertext:     &[u8],
) -> Vec<u8> {
    // Truncate the name to 255 bytes (the u8 length prefix can't hold more).
    let name_bytes = truncate_to_255(original_name);

    let total = 4 + 1 + 1 + 8 + 8 + 1 + name_bytes.len() + SALT_LEN + NONCE_LEN + ciphertext.len();
    let mut out = Vec::with_capacity(total);

    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&unix_now().to_le_bytes());
    out.extend_from_slice(&plaintext_size.to_le_bytes());
    out.push(name_bytes.len() as u8);
    out.extend_from_slice(&name_bytes);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);

    out
}

/// Parse raw bytes from disk into a `LbFile`.
pub fn parse(data: &[u8]) -> Result<LbFile<'_>> {
    // Minimum header before the variable-length name:
    // 4 magic + 1 version + 1 kind + 8 ts + 8 size + 1 name_len = 23
    const MIN_HEADER: usize = 23;

    if data.len() < MIN_HEADER {
        bail!("file is too small to be a valid .lb file");
    }

    if &data[0..4] != MAGIC {
        bail!("not a valid .lb file (magic bytes mismatch)");
    }

    let version = data[4];
    if version != VERSION {
        bail!(
            "unsupported .lb version: {} (this build supports version {})",
            version, VERSION
        );
    }

    let kind = PayloadKind::from_byte(data[5])?;

    let created_at    = u64::from_le_bytes(data[6..14].try_into().unwrap());
    let plaintext_size = u64::from_le_bytes(data[14..22].try_into().unwrap());

    let name_len  = data[22] as usize;
    let name_end  = 23 + name_len;

    if data.len() < name_end + SALT_LEN + NONCE_LEN {
        bail!("file is truncated in the header");
    }

    let original_name = std::str::from_utf8(&data[23..name_end])
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "<invalid UTF-8>".to_string());

    let salt_start = name_end;
    let mut salt   = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[salt_start..salt_start + SALT_LEN]);

    let nonce_start = salt_start + SALT_LEN;
    let mut nonce   = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[nonce_start..nonce_start + NONCE_LEN]);

    let ciphertext_start = nonce_start + NONCE_LEN;
    let ciphertext       = &data[ciphertext_start..];

    if ciphertext.is_empty() {
        bail!("file has no ciphertext payload");
    }

    Ok(LbFile {
        header: Header { version, kind, created_at, plaintext_size, original_name, salt, nonce },
        ciphertext,
    })
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn truncate_to_255(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    if b.len() <= 255 { b.to_vec() } else { b[..255].to_vec() }
}