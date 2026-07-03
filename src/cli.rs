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
    /// Encrypt a file or directory, producing a sibling `<name>.lb`
    Encrypt {
        /// File or directory to encrypt
        path: String,

        /// Delete the original file/directory after a successful encrypt
        #[arg(long)]
        delete_original: bool,
    },
    /// Decrypt a `.lb` file
    Decrypt {
        /// The .lb file to decrypt
        path: String,

        /// Output path (default: strips `.lb` from the input name)
        #[arg(short, long)]
        output: Option<String>,
    },
}