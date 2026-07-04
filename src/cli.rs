use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "lb")]
#[command(version = "0.2.0")]
#[command(about = "File Encryption Tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file or directory, producing a sibling `<name>.lb`
    Encrypt {
        /// File or directory to encrypt
        path: String,

        /// Delete the original after a successful encrypt (simple delete)
        #[arg(long)]
        delete_original: bool,

        /// Securely overwrite the original with random bytes before deleting
        /// (3-pass shred: zeros, ones, random). Implies --delete-original.
        #[arg(long)]
        shred: bool,
    },

    /// Decrypt a `.lb` file
    Decrypt {
        /// The .lb file to decrypt
        path: String,

        /// Output path (default: strips `.lb` from the input name)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Print metadata stored in a `.lb` file without decrypting it
    Info {
        /// The .lb file to inspect
        path: String,
    },
}