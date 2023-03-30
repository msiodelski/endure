#![warn(missing_docs)]

//! endure is a DHCP diagnostics tool.

use clap::Parser;
use cli::Cli;

pub mod cli;
pub mod dispatcher;
pub mod listener;
pub mod proto;

fn main() {
    let cli = Cli::parse();
    cli.run();
}
