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

use std::process::exit;

use crate::{
    dispatcher::{self, CsvOutputType},
    listener::Filter,
};
use clap::{Parser, Subcommand};
use futures::executor::block_on;

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
        interface_name: Vec<String>,
        /// Address to which the Prometheus endpoint is bound (e.g., 127.0.0.1:8080).
        /// Specifying this parameter enables the Prometheus endpoint (e.g., http://127.0.0.1:8080/metrics).
        #[arg(short, long)]
        prometheus_metrics_address: Option<String>,
        /// File location where the metrics should be periodically written in the CSV format.
        /// Use stdout to write the metrics to the console.
        #[arg(short, long)]
        csv_output: Option<String>,
        /// Specifies the interval at which the periodic report with metrics is generated.
        #[arg(short, long)]
        report_interval: Option<u64>,
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
                Commands::Collect {
                    interface_name: interface_names,
                    prometheus_metrics_address,
                    csv_output,
                    report_interval,
                } => {
                    // Create the dispatcher to multiplex tasks.
                    let mut dispatcher = dispatcher::Dispatcher::new();
                    // Only filter the BOOTP and DHCPv4 messages.
                    let filter = Filter::new().bootp_server_relay();
                    // Bind to the specified interfaces.
                    for interface_name in interface_names.iter() {
                        let result = dispatcher.add_listener(interface_name.as_str(), &filter);
                        if result.is_err() {
                            eprintln!("specified the same interface multiple names");
                            exit(128);
                        }
                    }
                    // Conditionally enable an export to Prometheus.
                    dispatcher.prometheus_metrics_address = prometheus_metrics_address;
                    // Conditionally enable periodic CSV reports.
                    dispatcher.csv_output =
                        csv_output.map(|csv_output| match csv_output.as_str() {
                            "stdout" => CsvOutputType::Stdout,
                            _ => CsvOutputType::File(csv_output),
                        });
                    // Set non-default interval for the periodic report.
                    if let Some(report_interval) = report_interval {
                        dispatcher.report_interval = report_interval;
                    }
                    // Run the dispatcher. It may fail starting the HTTP server or a CSV writer.
                    let result = block_on(dispatcher.dispatch());
                    match result {
                        Err(dispatcher::DispatchError::HttpServerError(err)) => {
                            eprintln!("failed to start an HTTP server: {}", err);
                            exit(128);
                        }
                        Err(dispatcher::DispatchError::CsvWriterError(err)) => {
                            eprintln!(
                                "failed to open a CSV file for the periodic metrics reports: {}",
                                err
                            );
                            exit(128);
                        }
                        _ => exit(0),
                    }
                }
            }
        }
    }
}
