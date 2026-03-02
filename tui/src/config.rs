use std::path::PathBuf;

use clap::Parser;

pub use o_clip_core::config::Config;

#[derive(Parser)]
#[command(name = "o-clip", about = "Clipboard manager with intranet sync")]
pub struct Cli {
    /// Path to config file (overrides default location).
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}
