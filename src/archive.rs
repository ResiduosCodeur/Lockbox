//! Directory archiving: pack a folder into a single byte blob, and unpack
//! it back out. This runs *before* encryption (pack) and *after* decryption
//! (unpack) — the crypto layer just sees one big blob either way.
//!
//! Binary format of the blob (little-endian integers):
//!
//! ```text
//! Repeat for each file:
//!   [4 bytes] path length (u32)
//!   [N bytes] relative path (UTF-8)
//!   [8 bytes] file size (u64)
//!   [M bytes] file contents
//!
//! Terminator:
//!   [4 bytes] 0u32  ← path length of zero means "end of entries"
//! ```

use std::path::Path;

use anyhow::{bail, Context, Result};
use walkdir::WalkDir;

/// Walks `folder` recursively and serialises every file into a single
/// `Vec<u8>` using the format described above.
pub fn pack(folder: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();

    for entry in WalkDir::new(folder).sort_by_file_name() {
        let entry = entry.with_context(|| format!("failed to read directory entry in {:?}", folder))?;

        // Skip directories — we only store files. The directory structure
        // is implicitly recreated on unpack via the relative paths.
        if entry.file_type().is_dir() {
            continue;
        }

        // Build a relative path (e.g. "subdir/file.txt") so that unpacking
        // recreates the same layout regardless of where the .lb file lives.
        let relative = entry
            .path()
            .strip_prefix(folder)
            .with_context(|| format!("path {:?} is not inside folder {:?}", entry.path(), folder))?;

        // Relative path as UTF-8 bytes. We use forward slashes explicitly
        // so .lb files are cross-platform (Windows paths use backslashes).
        let path_str = relative
            .to_str()
            .with_context(|| format!("path {:?} contains non-UTF-8 characters", relative))?
            .replace('\\', "/");

        let path_bytes = path_str.as_bytes();

        // Read the file contents.
        let contents = std::fs::read(entry.path())
            .with_context(|| format!("failed to read {:?}", entry.path()))?;

        // Write: [path_len u32][path bytes][file_size u64][file bytes]
        buf.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&(contents.len() as u64).to_le_bytes());
        buf.extend_from_slice(&contents);
    }

    // Terminator: a path length of zero signals end-of-entries.
    buf.extend_from_slice(&0u32.to_le_bytes());

    Ok(buf)
}

/// Deserialises a blob produced by `pack` and writes every file under
/// `output_dir`, creating subdirectories as needed.
pub fn unpack(data: &[u8], output_dir: &Path) -> Result<()> {
    let mut pos = 0;

    loop {
        // Read the 4-byte path length.
        let path_len = read_u32(data, pos)
            .context("archive is truncated while reading path length")?;
        pos += 4;

        // A path length of zero is the end-of-entries terminator.
        if path_len == 0 {
            break;
        }

        // Read the path string.
        let path_end = pos + path_len as usize;
        if path_end > data.len() {
            bail!("archive is truncated while reading file path");
        }
        let path_str = std::str::from_utf8(&data[pos..path_end])
            .context("file path in archive is not valid UTF-8")?;
        pos = path_end;

        // Reject any path that tries to escape the output directory
        // (e.g. "../../etc/passwd"). This is a security check — never
        // blindly unpack paths from untrusted archives without this.
        if path_str.contains("..") {
            bail!("archive contains suspicious path: {:?}", path_str);
        }

        // Read the 8-byte file size.
        let file_size = read_u64(data, pos)
            .context("archive is truncated while reading file size")?;
        pos += 8;

        // Read the file contents.
        let content_end = pos + file_size as usize;
        if content_end > data.len() {
            bail!("archive is truncated while reading file contents for {:?}", path_str);
        }
        let contents = &data[pos..content_end];
        pos = content_end;

        // Build the full output path and create parent directories.
        let out_path = output_dir.join(path_str);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {:?}", parent))?;
        }

        // Write the file.
        std::fs::write(&out_path, contents)
            .with_context(|| format!("failed to write {:?}", out_path))?;
    }

    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    data.get(pos..pos + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64(data: &[u8], pos: usize) -> Option<u64> {
    data.get(pos..pos + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}