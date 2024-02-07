//! cli is a module definining and handling the command line arguments
//! of the `endure` program.
//!
//! All new arguments and commands should be specified in this module.
//! The module uses the [clap] crate underneath.
//!
//! # Example Usage
//!
//! To parse the arguments and run the `endure` program with these arguments
//! simply do:
//!
//! ```rust
//! Cli::parse().run();
//! ```

use crate::{dispatcher, listener::Filter, timer};
use clap::{Parser, Subcommand};
use std::sync::atomic::Ordering;

/// A structure holding parsed program arguments.
#[derive(Parser)]
#[command(name = "endure")]
#[command(author = "Marcin Siodelski")]
#[command(about = "DHCP diagnostics utility", long_about=None)]
#[command(version)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

/// An enum that defines the supported subcommands.
#[derive(Subcommand)]
enum Commands {
    /// This command runs a traffic capture and analysis on the specified
    /// network interface.
    Collect {
        /// Interface name.
        #[arg(short, long)]
        interface_name: String,
    },
}

impl Cli {
    /// Runs the program for the specified arguments.
    ///
    /// # Example Usage
    ///
    /// ```rust
    /// Cli::parse().run();
    /// ```
    ///
    /// The function blocks for the traffic capturing commands. In that case,
    /// it internally installs a signal handler that can break the capture
    /// when the Ctrl+C pressed.
    pub fn run(self) {
        let args = Cli::parse();
        if let Some(commands) = args.commands {
            match commands {
                Commands::Collect { interface_name } => {
                    Cli::install_signal_handler();
                    let mut dispatcher = dispatcher::Dispatcher::new();
                    let filter = Filter::new().bootp_server_relay();
                    dispatcher
                        .add_listener(interface_name.as_str(), filter)
                        .expect("listener already added");
                    dispatcher
                        .add_timer(timer::Type::DataScrape, 3000)
                        .expect("timer already added");
                    dispatcher.dispatch();
                }
            }
        }
    }

    /// Installs the signal handler to break the traffic capture,
    ///
    /// The signal handler runs in a thread. It sets the [dispatcher::STOP] value
    /// to notify the dispatcher that the program is terminating.
    fn install_signal_handler() {
        ctrlc::set_handler(|| dispatcher::STOP.store(true, Ordering::Release))
            .expect("error setting Ctrl+C handler");
    }
}
