mod cli;
mod crypto;
mod format;

use anyhow::{bail, Context, Result};
use cli::{Cli, Commands};
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            file,
            delete_original,
        } => encrypt_file(&file, delete_original),
        Commands::Decrypt { file, output } => decrypt_file(&file, output),
    }
}

fn encrypt_file(file: &str, delete_original: bool) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("failed to read {file}"))?;

    println!("Password: ");
    let password = rpassword::read_password()?;
    println!("Confirm password: ");
    let confirm = rpassword::read_password()?;

    if password != confirm {
        bail!("passwords did not match");
    }
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    let salt = crypto::generate_salt();
    let nonce = crypto::generate_nonce();
    let key = crypto::derive_key(&password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &data)?;

    let output_bytes = format::write(&salt, &nonce, &ciphertext);

    let output_path = format!("{file}.lb");
    std::fs::write(&output_path, output_bytes)
        .with_context(|| format!("failed to write {output_path}"))?;

    if delete_original {
        std::fs::remove_file(file).with_context(|| format!("failed to delete {file}"))?;
    }

    println!("Encrypted -> {output_path}");
    Ok(())
}

fn decrypt_file(file: &str, output: Option<String>) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("failed to read {file}"))?;

    let parsed = format::parse(&data)?;

    println!("Password: ");
    let password = rpassword::read_password()?;

    let key = crypto::derive_key(&password, &parsed.salt)?;
    let plaintext = crypto::decrypt(&key, &parsed.nonce, parsed.ciphertext)?;

    let output_path = output.unwrap_or_else(|| default_output_path(file));
    std::fs::write(&output_path, plaintext)
        .with_context(|| format!("failed to write {output_path}"))?;

    println!("Decrypted -> {output_path}");
    Ok(())
}

/// Strips a trailing `.lb` extension if present, otherwise appends
/// `.decrypted` so we never silently overwrite anything unexpected.
fn default_output_path(file: &str) -> String {
    match file.strip_suffix(".lb") {
        Some(stripped) => stripped.to_string(),
        None => format!("{file}.decrypted"),
    }
}