mod archive;
mod cli;
mod crypto;
mod format;
mod shred;

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use format::PayloadKind;
use indicatif::{ProgressBar, ProgressStyle};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { path, delete_original, shred } => {
            encrypt(&path, delete_original, shred)
        }
        Commands::Decrypt { path, output } => decrypt(&path, output),
        Commands::Info    { path }         => info(&path),
    }
}

// ── encrypt ───────────────────────────────────────────────────────────────────

fn encrypt(path: &str, delete_original: bool, do_shred: bool) -> Result<()> {
    let p = Path::new(path);

    if !p.exists() {
        bail!("path does not exist: {path}");
    }

    // Collect the plaintext payload.
    let (plaintext, kind) = if p.is_dir() {
        let pb = spinner("Packing directory...");
        let blob = archive::pack(p)
            .with_context(|| format!("failed to pack directory {path}"))?;
        pb.finish_with_message(format!("Packed {} bytes", blob.len()));
        (blob, PayloadKind::Directory)
    } else {
        let pb = spinner("Reading file...");
        let data = std::fs::read(p)
            .with_context(|| format!("failed to read {path}"))?;
        pb.finish_with_message(format!("Read {} bytes", data.len()));
        (data, PayloadKind::SingleFile)
    };

    let plaintext_size = plaintext.len() as u64;

    // Original name: just the file/folder name, not the full path.
    let original_name = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string();

    // Password prompt.
    let password = prompt_new_password()?;

    // Key derivation (show a spinner — Argon2 takes a moment).
    let pb   = spinner("Deriving key...");
    let salt = crypto::generate_salt();
    let key  = crypto::derive_key(&password, &salt)?;
    pb.finish_with_message("Key derived");

    // Encryption (progress bar sized to plaintext bytes).
    let pb         = bytes_bar(plaintext_size, "Encrypting...");
    let nonce      = crypto::generate_nonce();
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext)?;
    pb.finish_with_message("Encrypted");

    // Assemble and write the .lb file.
    let pb = spinner("Writing .lb file...");
    let output_bytes = format::write(
        kind,
        &original_name,
        plaintext_size,
        &salt,
        &nonce,
        &ciphertext,
    );
    let output_path = format!("{path}.lb");
    std::fs::write(&output_path, &output_bytes)
        .with_context(|| format!("failed to write {output_path}"))?;
    pb.finish_with_message(format!("Written {} bytes", output_bytes.len()));

    println!("\n✔ Encrypted -> {output_path}");

    // Shred or delete the original.
    if do_shred {
        let pb = spinner("Shredding original...");
        shred::shred(p)
            .with_context(|| format!("failed to shred {path}"))?;
        pb.finish_with_message(format!("Shredded: {path}"));
        println!("✔ Shredded original: {path}");
    } else if delete_original {
        if p.is_dir() {
            std::fs::remove_dir_all(p)
                .with_context(|| format!("failed to delete directory {path}"))?;
        } else {
            std::fs::remove_file(p)
                .with_context(|| format!("failed to delete {path}"))?;
        }
        println!("✔ Deleted original: {path}");
    }

    Ok(())
}

// ── decrypt ───────────────────────────────────────────────────────────────────

fn decrypt(path: &str, output: Option<String>) -> Result<()> {
    let pb   = spinner("Reading .lb file...");
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read {path}"))?;
    pb.finish_with_message(format!("Read {} bytes", data.len()));

    let parsed = format::parse(&data)?;

    let password = prompt_password()?;

    // Key derivation.
    let pb  = spinner("Deriving key...");
    let key = crypto::derive_key(&password, &parsed.header.salt)?;
    pb.finish_with_message("Key derived");

    // Decryption.
    let pb        = bytes_bar(parsed.header.plaintext_size, "Decrypting...");
    let plaintext = crypto::decrypt(&key, &parsed.header.nonce, parsed.ciphertext)?;
    pb.finish_with_message("Decrypted");

    match parsed.header.kind {
        PayloadKind::SingleFile => {
            let out = output.unwrap_or_else(|| default_output_path(path));
            let pb  = spinner("Writing file...");
            std::fs::write(&out, &plaintext)
                .with_context(|| format!("failed to write {out}"))?;
            pb.finish_with_message(format!("Written {out}"));
            println!("\n✔ Decrypted -> {out}");
        }

        PayloadKind::Directory => {
            let out     = output.unwrap_or_else(|| default_output_path(path));
            let out_dir = Path::new(&out);
            std::fs::create_dir_all(out_dir)
                .with_context(|| format!("failed to create output directory {out}"))?;
            let pb = spinner("Unpacking files...");
            archive::unpack(&plaintext, out_dir)
                .with_context(|| format!("failed to unpack archive into {out}"))?;
            pb.finish_with_message(format!("Unpacked into {out}"));
            println!("\n✔ Decrypted -> {out}/");
        }
    }

    Ok(())
}

// ── info ──────────────────────────────────────────────────────────────────────

fn info(path: &str) -> Result<()> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read {path}"))?;

    let parsed = format::parse(&data)?;
    let h      = &parsed.header;

    // Format the timestamp as a human-readable date.
    let created = format_timestamp(h.created_at);

    println!();
    println!("  File        : {path}");
    println!("  LB version  : {}", h.version);
    println!("  Type        : {}", h.kind.label());
    println!("  Created     : {created}");
    println!("  Origin name : {}", h.original_name);
    println!("  Plain size  : {}", human_bytes(h.plaintext_size));
    println!("  Enc size    : {}", human_bytes(parsed.ciphertext.len() as u64));
    println!("  Algorithm   : AES-256-GCM + Argon2id");
    println!();

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

fn prompt_password() -> Result<String> {
    println!("Password: ");
    let pw = rpassword::read_password()?;
    Ok(pw)
}

fn default_output_path(path: &str) -> String {
    match path.strip_suffix(".lb") {
        Some(s) => s.to_string(),
        None    => format!("{path}.decrypted"),
    }
}

/// A spinner for steps where we don't know exact progress (e.g. key derivation).
fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// A bytes-based progress bar for encrypt/decrypt steps.
fn bytes_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.green/dim}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb.set_message(msg.to_string());
    // Since AES-GCM encrypts in one shot (not streamed), jump to 100%
    // immediately after the call returns — the bar shows the data size
    // so the user knows what was processed.
    pb.set_position(total);
    pb
}

fn format_timestamp(unix: u64) -> String {
    // Build a readable date from a Unix timestamp without pulling in chrono.
    // We convert to system time and use Debug formatting as a fallback,
    // but construct a proper date string manually.
    let secs = unix;
    let dt   = UNIX_EPOCH + Duration::from_secs(secs);

    // Days since epoch -> calendar date (Gregorian, simplified)
    let days        = secs / 86400;
    let time_of_day = secs % 86400;
    let (y, m, d)   = days_to_ymd(days);
    let hh          = time_of_day / 3600;
    let mm          = (time_of_day % 3600) / 60;
    let ss          = time_of_day % 60;

    // Suppress unused variable warning for dt
    let _ = dt;

    format!("{y}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// Converts days since Unix epoch (1970-01-01) to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // 400-year Gregorian cycle = 146097 days
    let mut year = 1970u64;

    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }

    let month_days: &[u64] = if is_leap(year) {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &md in month_days {
        if days < md { break; }
        days -= md;
        month += 1;
    }

    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn human_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if n >= GB      { format!("{:.2} GB ({n} bytes)", n as f64 / GB as f64) }
    else if n >= MB { format!("{:.2} MB ({n} bytes)", n as f64 / MB as f64) }
    else if n >= KB { format!("{:.2} KB ({n} bytes)", n as f64 / KB as f64) }
    else            { format!("{n} bytes") }
}