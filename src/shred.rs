//! Secure file deletion. A normal `fs::remove_file` just tells the OS the
//! space is free — the bytes are still on disk until something else overwrites
//! them. Shredding overwrites the file contents with random bytes first,
//! making recovery much harder.
//!
//! Note: on SSDs with wear-levelling or filesystems with copy-on-write
//! (e.g. btrfs, APFS), overwriting in-place isn't guaranteed to hit the same
//! physical sectors. For most threat models this is still far better than a
//! plain delete. Full disk encryption is the real answer for SSDs.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use rand::RngCore;

/// Overwrites every file under `path` with random bytes, then deletes it.
/// If `path` is a directory, recurses into it and shreds every file inside
/// before removing the directory tree.
pub fn shred(path: &Path) -> Result<()> {
    if path.is_dir() {
        shred_dir(path)
    } else {
        shred_file(path)
    }
}

fn shred_dir(dir: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir)
        .contents_first(true)   // files before their parent dirs
    {
        let entry = entry.with_context(|| format!("failed to read entry in {:?}", dir))?;
        let p     = entry.path();

        if p.is_file() {
            shred_file(p)?;
        } else if p.is_dir() {
            std::fs::remove_dir(p)
                .with_context(|| format!("failed to remove directory {:?}", p))?;
        }
    }
    Ok(())
}

fn shred_file(path: &Path) -> Result<()> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("failed to stat {:?}", path))?
        .len() as usize;

    if len > 0 {
        // Three passes: all-zeros, all-ones, random.
        // (The DoD 5220.22-M standard uses a similar pattern.)
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open {:?} for shredding", path))?;

        overwrite(&mut file, len, &vec![0x00; len])?;
        overwrite(&mut file, len, &vec![0xFF; len])?;

        let mut random = vec![0u8; len];
        rand::rng().fill_bytes(&mut random);
        overwrite(&mut file, len, &random)?;

        file.flush()
            .with_context(|| format!("failed to flush {:?}", path))?;
    }

    std::fs::remove_file(path)
        .with_context(|| format!("failed to remove {:?}", path))?;

    Ok(())
}

fn overwrite(file: &mut std::fs::File, len: usize, data: &[u8]) -> Result<()> {
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(0))
        .context("failed to seek to start of file")?;
    file.write_all(&data[..len])
        .context("failed to write shred pass")?;
    Ok(())
}