#![warn(missing_docs)]

//! endure is a DHCP diagnostics tool.

use clap::Parser;
use cli::Cli;

pub mod analyzer;
pub mod cli;
pub mod dispatcher;
pub mod listener;
pub mod proto;
pub mod thread;
pub mod timer;

fn main() {
    let cli = Cli::parse();
    cli.run();
}
