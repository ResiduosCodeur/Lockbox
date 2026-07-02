use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "lb")]
#[command(version = "0.1.0")]
#[command(about = "File Encryption Tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file, producing a sibling `<file>.lb`
    Encrypt {
        file: String,

        /// Delete the original plaintext file after a successful encrypt
        #[arg(long)]
        delete_original: bool,
    },
    /// Decrypt a `.lb` file, producing the original file
    Decrypt {
        file: String,

        /// Output path. Defaults to the input path with `.lb` stripped.
        #[arg(short, long)]
        output: Option<String>, //custon output file name - optional
    },
}