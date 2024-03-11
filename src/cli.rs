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

use crate::dispatcher::{self, CsvOutputType};
use endure_lib::listener::{self, Filter};

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
        #[arg(short, long, group = "interface", required = true)]
        interface_name: Vec<String>,
        #[arg(long, group = "interface", action)]
        /// Enables listening on the loopback interface. It is an alias for -l [loopback-inteface-name].
        loopback: bool,
        /// Address and port where the program opens an HTTP server and exposes REST API
        /// and Prometheus exporter are bound.
        #[arg(short = 'a', long)]
        http_address: Option<String>,
        /// File location where the metrics should be periodically written in the CSV format.
        /// Use stdout to write the metrics to the console.
        #[arg(short, long)]
        csv_output: Option<String>,
        /// Specifies the interval at which the periodic metrics report is generated.
        #[arg(short, long, value_parser = clap::value_parser!(u64).range(1..), default_value_t = 5)]
        report_interval: u64,
        /// Enables the metrics export to Prometheus via the [http-address]/metrics endpoint.
        #[arg(long, action)]
        prometheus: bool,
        /// Enables the REST API on [http-address]/api endpoint.
        #[arg(long, action)]
        api: bool,
        /// Enables server sent events (SSE).
        #[arg(long, action)]
        sse: bool,
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
                    interface_name: mut interface_names,
                    loopback,
                    http_address,
                    csv_output,
                    report_interval,
                    prometheus,
                    api,
                    sse,
                } => {
                    // Check if the loopback interface has been explicitly.
                    if loopback {
                        if let Some(loopback_name) = listener::Listener::loopback_name() {
                            interface_names.push(loopback_name)
                        }
                    }
                    // Create the dispatcher to multiplex tasks.
                    let mut dispatcher = dispatcher::Dispatcher::new();
                    // Only filter the BOOTP and DHCPv4 messages.
                    let filter = Filter::new().bootp_server_relay();
                    // Bind to the specified interfaces.
                    for interface_name in interface_names.iter() {
                        let result = dispatcher.add_listener(interface_name.as_str(), &filter);
                        if let Some(err) = result.err() {
                            eprintln!("{}", err.to_string());
                            exit(128);
                        }
                    }
                    match http_address {
                        None => {
                            if prometheus || api || sse {
                                eprintln!("'http_address' is required when using '--prometheus', '--api' or '--sse flags");
                                exit(128);
                            }
                        }
                        Some(_) => {
                            if !prometheus && !api && !sse {
                                eprintln!("'http_address' is only valid with '--prometheus', '--api' and '--sse' flags");
                                exit(128);
                            }
                        }
                    }
                    // Make sure the HTTP server address has been specified if we want to
                    // export the metrics to Prometheus, expose the API or SSE.
                    if (prometheus || api || sse) && http_address.is_none() {
                        eprintln!("http_address is required to enable Prometheus export, API endpoint and/or events");
                        exit(128);
                    }
                    // Conditionally enable an export to Prometheus and/or API.
                    dispatcher.http_server_address = http_address;
                    dispatcher.enable_prometheus = prometheus;
                    dispatcher.enable_api = api;
                    dispatcher.enable_sse = sse;
                    // Conditionally enable periodic CSV reports.
                    dispatcher.csv_output =
                        csv_output.map(|csv_output| match csv_output.as_str() {
                            "stdout" => CsvOutputType::Stdout,
                            _ => CsvOutputType::File(csv_output),
                        });
                    // Set interval for the periodic report.
                    dispatcher.report_interval = report_interval;

                    // Run the dispatcher. It may fail starting the HTTP server or a CSV writer.
                    let result = block_on(dispatcher.dispatch());
                    match result {
                        Err(err) => {
                            eprintln!("{}", err.to_string());
                            exit(128);
                        }
                        _ => exit(0),
                    }
                }
            }
        }
    }
}
