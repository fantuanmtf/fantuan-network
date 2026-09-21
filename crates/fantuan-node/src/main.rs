//! `fantuan-node` command line interface.

use anyhow::Result;
use clap::{Parser, Subcommand};
use fantuan_node::{default_config_path, identity_cmd, load_config, run, send};
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
    /// Send an end-to-end encrypted message through a bootstrap peer.
    Send {
        /// Destination fingerprint or uid.
        #[arg(long)]
        to: String,
        /// Next-hop I2P destination (bootstrap peer).
        #[arg(long)]
        via: String,
        /// Message text.
        #[arg(long)]
        message: String,
    },
    /// List known peers from the trust store.
    Peers,
    /// Manage trust.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
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

#[derive(Subcommand)]
enum TrustCommand {
    /// Create a signed trust vouch for a peer.
    Set {
        /// Fingerprint or uid of the peer.
        #[arg(long)]
        target: String,
        /// Trust level 0..=3.
        #[arg(long)]
        level: u8,
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
        Command::Send { to, via, message } => {
            send::send(&config, &via, &to, &message).await?;
        }
        Command::Peers => {
            let peers = identity_cmd::list_peers(&config)?;
            if peers.is_empty() {
                println!("no peers known");
            }
            for peer in peers {
                println!(
                    "{}  trust={:.2}  {}",
                    peer.fingerprint, peer.trust_score, peer.uid
                );
            }
        }
        Command::Trust { command } => match command {
            TrustCommand::Set { target, level } => {
                let fingerprint = identity_cmd::set_trust(&config, &target, level)?;
                println!("trust {level} recorded for {fingerprint}");
            }
        },
        Command::Config => {
            println!("{}", default_config_path().display());
        }
    }
    Ok(())
}
