use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use argon2::Argon2;
use clap::{Parser, Subcommand};
use rand::RngCore;

#[derive(Parser)]
#[command(name = "lb")]
#[command(version = "0.1.0")]
#[command(about = "File Encryption Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt { file: String },
    Decrypt { file: String },
}

fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|error| anyhow!("failed to derive encryption key: {error}"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| anyhow!("failed to initialize cipher: {error}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|error| anyhow!("failed to encrypt data: {error}"))?;

    // Store:
    // [salt][nonce][ciphertext]
    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { file } => {
            println!("Encrypting {}", file);

            let data = std::fs::read(&file)?;

            println!("Password:");
            let password = rpassword::read_password()?;

            let encrypted = encrypt_data(&data, &password)?;

            std::fs::write(format!("{}.lb", file), encrypted)?;

            println!("Encrypted successfully");
        }
        Commands::Decrypt { file } => {
            println!("Decrypting {}", file);
        }
    }

    Ok(())
}
