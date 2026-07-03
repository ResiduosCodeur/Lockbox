mod archive;
mod cli;
mod crypto;
mod format;

use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use format::PayloadKind;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { path, delete_original } => encrypt(&path, delete_original),
        Commands::Decrypt { path, output }          => decrypt(&path, output),
    }
}

// ── encrypt ──────────────────────────────────────────────────────────────────

fn encrypt(path: &str, delete_original: bool) -> Result<()> {
    let p = Path::new(path);

    if !p.exists() {
        bail!("path does not exist: {path}");
    }

    // Collect the plaintext payload and remember whether it was a file or dir.
    let (plaintext, kind) = if p.is_dir() {
        println!("Packing directory: {path}");
        let blob = archive::pack(p)
            .with_context(|| format!("failed to pack directory {path}"))?;
        (blob, PayloadKind::Directory)
    } else {
        let data = std::fs::read(p)
            .with_context(|| format!("failed to read {path}"))?;
        (data, PayloadKind::SingleFile)
    };

    // Ask for a password (twice, to catch typos).
    let password = prompt_new_password()?;

    // Derive key, encrypt.
    let salt       = crypto::generate_salt();
    let nonce      = crypto::generate_nonce();
    let key        = crypto::derive_key(&password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext)?;

    // Assemble the .lb file and write it.
    let output_bytes = format::write(kind, &salt, &nonce, &ciphertext);
    let output_path  = format!("{path}.lb");
    std::fs::write(&output_path, output_bytes)
        .with_context(|| format!("failed to write {output_path}"))?;

    println!("Encrypted -> {output_path}");

    // Optionally remove the original.
    if delete_original {
        if p.is_dir() {
            std::fs::remove_dir_all(p)
                .with_context(|| format!("failed to delete directory {path}"))?;
        } else {
            std::fs::remove_file(p)
                .with_context(|| format!("failed to delete {path}"))?;
        }
        println!("Deleted original: {path}");
    }

    Ok(())
}

// ── decrypt ──────────────────────────────────────────────────────────────────

fn decrypt(path: &str, output: Option<String>) -> Result<()> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read {path}"))?;

    let parsed = format::parse(&data)?;

    let password = prompt_password()?;

    let key       = crypto::derive_key(&password, &parsed.salt)?;
    let plaintext = crypto::decrypt(&key, &parsed.nonce, parsed.ciphertext)?;

    match parsed.kind {
        PayloadKind::SingleFile => {
            let out = output.unwrap_or_else(|| default_output_path(path));
            std::fs::write(&out, &plaintext)
                .with_context(|| format!("failed to write {out}"))?;
            println!("Decrypted -> {out}");
        }

        PayloadKind::Directory => {
            // For directories, the output is a folder (not a file).
            let out = output.unwrap_or_else(|| default_output_path(path));
            let out_dir = Path::new(&out);
            std::fs::create_dir_all(out_dir)
                .with_context(|| format!("failed to create output directory {out}"))?;
            archive::unpack(&plaintext, out_dir)
                .with_context(|| format!("failed to unpack archive into {out}"))?;
            println!("Decrypted -> {out}/");
        }
    }

    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Asks for a password twice and returns it if both entries match.
fn prompt_new_password() -> Result<String> {
    let password = prompt_password()?;

    println!("Confirm password: ");
    let confirm = rpassword::read_password()?;

    if password != confirm {
        bail!("passwords did not match");
    }
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    Ok(password)
}

/// Asks for a password once (used on decrypt).
fn prompt_password() -> Result<String> {
    println!("Password: ");
    let pw = rpassword::read_password()?;
    Ok(pw)
}

/// Strips a trailing `.lb` if present, otherwise appends `.decrypted`.
fn default_output_path(path: &str) -> String {
    match path.strip_suffix(".lb") {
        Some(s) => s.to_string(),
        None    => format!("{path}.decrypted"),
    }
}