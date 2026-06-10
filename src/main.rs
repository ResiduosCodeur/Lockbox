use clap::{Parser, Subcommand};

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
    Encrypt {
        file: String,
    },
    Decrypt {
        file: String,
    },
}

fn main() {

let cli = Cli::parse();

match cli.command {
    Commands::Encrypt { file } => {
        println!("Encrypting {}", file);
    }

    Commands::Decrypt { file } => {
        println!("Decrypting {}", file);
    }
}

}