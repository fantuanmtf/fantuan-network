//! `fantuan-sim` command line entry point.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fantuan-sim",
    version,
    about = "Offline discrete-event anonymity simulator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a scenario and write its transcript as JSON.
    Run {
        /// Scenario name (for example `calibration-uniform`).
        #[arg(long)]
        scenario: String,
        /// Deterministic RNG seed.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Output JSON path.
        #[arg(long)]
        out: PathBuf,
    },
    /// List available scenarios.
    List,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            scenario,
            seed,
            out,
        } => {
            let transcript = match fantuan_sim::run(&scenario, seed) {
                Ok(transcript) => transcript,
                Err(error) => {
                    eprintln!("error: {error}");
                    std::process::exit(1);
                }
            };
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(error) = std::fs::create_dir_all(parent) {
                        eprintln!("error: cannot create {}: {error}", parent.display());
                        std::process::exit(1);
                    }
                }
            }
            let json = match serde_json::to_string_pretty(&transcript) {
                Ok(json) => json,
                Err(error) => {
                    eprintln!("error: cannot serialize transcript: {error}");
                    std::process::exit(1);
                }
            };
            if let Err(error) = std::fs::write(&out, json) {
                eprintln!("error: cannot write {}: {error}", out.display());
                std::process::exit(1);
            }
            println!(
                "scenario={} seed={} observations={} -> {}",
                transcript.scenario,
                transcript.seed,
                transcript.observations.len(),
                out.display()
            );
        }
        Command::List => {
            println!("{}", fantuan_sim::CALIBRATION_UNIFORM);
            println!("{}", fantuan_sim::CALIBRATION_TIMED);
        }
    }
}
