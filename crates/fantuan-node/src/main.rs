//! `fantuan-node` command line interface.

use anyhow::Result;
use clap::{Parser, Subcommand};
use fantuan_node::{default_config_path, identity_cmd, load_config, run};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fantuan-node",
    version,
    about = "Fantuan Network node (I2P + OpenPGP + Noise)"
)]
struct Cli {
    /// Configuration file (default: ~/.fantuan/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the node identity.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Run the node until Ctrl-C.
    Run {
        /// Additional peer destination to dial (repeatable).
        #[arg(long = "connect")]
        connect: Vec<String>,
    },
    /// Connect to a node, optionally send a message, then measure a ping.
    Ping {
        /// Peer I2P destination (base64) or hostname.
        #[arg(long)]
        destination: String,
        /// Optional text message to send before pinging.
        #[arg(long)]
        message: Option<String>,
    },
    /// Print the configuration file path in use.
    Config,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Generate an OpenPGP identity and a persistent I2P destination.
    Init {
        /// Display name (defaults to the configured display name).
        #[arg(long)]
        uid: Option<String>,
        /// Overwrite an existing identity.
        #[arg(long)]
        force: bool,
    },
    /// Print identity details.
    Show,
    /// Export the public identity material.
    Export {
        /// Destination directory.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Verify and import a peer descriptor into the trust store.
    Import {
        /// Descriptor CBOR file.
        #[arg(long)]
        descriptor: PathBuf,
        /// Detached signature file.
        #[arg(long)]
        signature: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = load_config(cli.config.as_deref())?;

    match cli.command {
        Command::Identity { command } => match command {
            IdentityCommand::Init { uid, force } => {
                let identity = identity_cmd::init(&config, uid.as_deref(), force).await?;
                println!("identity created in {}", config.identity_dir().display());
                print!("{}", identity_cmd::show(&identity));
            }
            IdentityCommand::Show => {
                let identity = identity_cmd::load_identity(&config)?;
                print!("{}", identity_cmd::show(&identity));
            }
            IdentityCommand::Export { out_dir } => {
                let files = identity_cmd::export(&config, &out_dir)?;
                for file in files {
                    println!("exported {}", file.display());
                }
            }
            IdentityCommand::Import {
                descriptor,
                signature,
            } => {
                let imported = identity_cmd::import(&config, &descriptor, &signature)?;
                println!("imported {} ({})", imported.uid, imported.fingerprint);
            }
        },
        Command::Run { connect } => {
            run::run(config, connect).await?;
        }
        Command::Ping {
            destination,
            message,
        } => {
            run::ping(&config, &destination, message.as_deref()).await?;
        }
        Command::Config => {
            println!("{}", default_config_path().display());
        }
    }
    Ok(())
}
