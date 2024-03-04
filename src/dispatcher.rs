//! `dispatcher` is a module serving as a core of the endure program.
//!
//! It installs the listeners and receives captured packets from them.
//! The dispatcher will eventually send the received packets to the
//! specialized modules for analysis. In this early version, it merely
//! prints the received packets in the binary form.
//!
//! # Example Usage
//!
//! The following snippet shows how to initialize and run the dispatcher
//! to capture DHCPv4 traffic on the bridge100 interface:
//!
//! ```rust
//! let mut dispatcher = dispatcher::Dispatcher::new();
//! let filter = Filter::new().bootp_server_relay();
//! dispatcher.add_listener("bridge100", filter).expect("listener already added");
//! dispatcher.prometheus_metrics_address = "127.0.0.1:8080"
//! dispatcher.csv_output = CsvOutputType::File("./csv_metrics.csv")
//! dispatcher.dispatch();
//! ```

use std::{
    collections::HashMap,
    io::stdout,
    sync::{Arc, Mutex},
};

use actix_web::{web, App, HttpResponse, HttpServer, Result};
use csv::{Writer, WriterBuilder};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::{signal, time};

use crate::{
    analyzer::Analyzer,
    listener::{Filter, Listener, PacketWrapper},
};

/// An enum of errors returned by the [Dispatcher].
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Returned on an attempt to add a duplicate listener.
    ///
    /// There must be at most one listener bound to an interface.
    /// An attempt to bind another listener to the same interface
    /// yields this error. It can be returned by the
    /// [`Dispatcher::add_listener`] function.
    AddListenerExists,
}

/// A HTTP handler for exposing metrics to Prometheus.
///
/// # Parameters
///
/// - `registry` - a Prometheus registry.
async fn metrics_handler(registry: web::Data<Mutex<Registry>>) -> Result<HttpResponse> {
    let registry = registry.lock().unwrap();
    let mut body = String::new();
    encode(&mut body, &registry).unwrap();
    Ok(HttpResponse::Ok()
        .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
        .body(body))
}

/// Location of the CSV metrics reports.
pub enum CsvOutputType {
    /// CSV metrics are printed to a console.
    Stdout,
    /// CSV metrics are printed to a specified file.
    ///
    /// The enum value specifies the file path.
    File(String),
}

/// Runs the installed listeners until the stop signal occurs.
pub struct Dispatcher {
    listeners: HashMap<String, Listener>,

    /// Address and port where metrics endpoint is bound.
    ///
    /// If it is `None` the metrics for Prometheus is disabled.
    pub prometheus_metrics_address: Option<String>,

    /// Location where the periodic CSV reports are written.
    ///
    /// If it is `None` the periodic CSV reports are not generated.
    pub csv_output: Option<CsvOutputType>,

    /// An interval of the periodic metrics report.
    ///
    /// The interval is specified in seconds and it defaults to 5 seconds.
    /// This value is ignored when generating the periodic report is not
    /// enabled with the [`Dispatcher::csv_output`] parameter.
    pub report_interval: u64,
}

impl Dispatcher {
    /// Instantiates the dispatcher.
    ///
    /// It creates an empty map of listeners. The caller should add
    /// the listeners using the [`Dispatcher::add_listener`] function.
    pub fn new() -> Dispatcher {
        Dispatcher {
            listeners: HashMap::new(),
            prometheus_metrics_address: None,
            csv_output: None,
            report_interval: 10,
        }
    }

    /// Attempts to add a listener for a device.
    ///
    /// The listener is installed for the specific device (i.e., interface).
    /// If there is another listener installed for this device already
    /// it returns [`Error::AddListenerExists`] error.
    ///
    /// The [Filter] applies filtering rules for packets capturing. For example,
    /// it can be used to filter only BOOTP packets, only UDP packets, select
    /// port number etc.
    pub fn add_listener(&mut self, interface_name: &str, filter: &Filter) -> Result<(), Error> {
        if self.listeners.contains_key(interface_name) {
            return Err(Error::AddListenerExists);
        }
        let mut listener = Listener::new(interface_name);
        listener.filter(filter);
        self.listeners.insert(interface_name.to_string(), listener);
        Ok(())
    }

    /// Starts an HTTP server enabling an endpoint for Prometheus.
    ///
    /// The metrics endpoint is only enabled when user has specified
    /// a binding address for the Prometheus endpoint.
    ///
    /// # Parameters
    ///
    /// - `analyzer` - an analyzer instance implementing a Prometheus
    ///   metrics collector.
    fn conditionally_start_http_server(&self, analyzer: Analyzer) {
        // Check if metrics export to Prometheus should be enabled.
        if let Some(prometheus_metrics_address) = &self.prometheus_metrics_address {
            // Create the prometheus registry and register our analyzer
            // as a metrics collector. The metrics collector encodes the
            // metrics into the format readable by prometheus.
            let mut registry = Registry::default();
            registry.register_collector(Box::new(analyzer));
            let registry = web::Data::new(Mutex::new(registry));
            // Create HTTP server.
            let server = HttpServer::new(move || {
                App::new()
                    .app_data(registry.clone())
                    .service(web::resource("/metrics").route(web::get().to(metrics_handler)))
            })
            .bind(prometheus_metrics_address)
            .unwrap()
            .run();
            // Run the HTTP server asynchronously.
            tokio::spawn(async move { server.await });
        }
    }

    /// Enables generation of the periodic metrics report in CSV format.
    ///
    /// # Parameters
    ///
    /// - `analyzer` - an analyzer instance providing the metrics for the
    ///   CSV writer.
    /// - `writer` - a CSV writer instance in one of the two possible variants
    ///   (i.e., [`Writer<stdout>`] or [`Writer<File>`]).
    fn conditionally_enable_csv_reports<T>(
        &self,
        analyzer: Arc<Mutex<Analyzer>>,
        mut writer: Writer<T>,
    ) where
        T: std::io::Write + Send + 'static,
    {
        let mut interval = tokio::time::interval(time::Duration::from_secs(self.report_interval));
        let report_future = async move {
            loop {
                interval.tick().await;
                let report = { analyzer.lock().unwrap().current_dhcpv4_report() };
                writer.serialize(report).unwrap();
                let _ = writer.flush();
                interval.reset();
            }
        };
        tokio::spawn(report_future);
    }

    /// Dispatches all requests and events in the program.
    ///
    /// This the actual entry point of the program processing all received
    /// requests and generating an output. It is multiplexing different types
    /// of tasks asynchronously. In particular it:
    ///
    /// - receives the packets from the network and sends them to the analysis,
    /// - runs an HTTP service exporting metrics to the external entities (like Prometheus),
    /// - generates periodic tasks such as writing periodic reports.
    pub async fn dispatch(mut self) {
        // Open a channel to receive the packets captured by the listeners in
        // the threads.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PacketWrapper>(100);
        let tx = Arc::new(Mutex::new(tx));
        // Open the listeners. The listeners use the tx side of the channel to
        // send the received packets to the main thread.
        for listener in &mut self.listeners {
            listener.1.start(Arc::clone(&tx));
        }
        // Instantiate the analyzer. The analyzer examines the received traffic but
        // it also serves as a Prometheus metrics collector.
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();

        // Start the HTTP server exporting the metrics to Prometheus if a
        // user has specified the metrics endpoint address.
        self.conditionally_start_http_server(analyzer.clone());

        // Check if the user has specified the output location for the CSV reports.
        // In this case, it opens a writer for and runs an asynchronous task writing
        // the periodic reports.
        let analyzer = Arc::new(Mutex::new(analyzer));
        if let Some(csv_output) = &self.csv_output {
            match csv_output {
                // Write to stdout.
                CsvOutputType::Stdout => self.conditionally_enable_csv_reports(
                    analyzer.clone(),
                    WriterBuilder::new().has_headers(true).from_writer(stdout()),
                ),
                // Write to a file.
                CsvOutputType::File(csv_output) => self.conditionally_enable_csv_reports(
                    analyzer.clone(),
                    WriterBuilder::new()
                        .has_headers(true)
                        .from_path(csv_output)
                        .unwrap(),
                ),
            }
        }
        // Schedule packets capturing.
        let receive_future = async move {
            loop {
                let packet = rx.recv().await;
                match packet {
                    Some(packet) => analyzer.lock().unwrap().receive(packet),
                    None => return,
                }
            }
        };
        tokio::spawn(receive_future);

        // Install Ctrl-C signal handler to exit the program when it is pressed.
        let ctrl_c = signal::ctrl_c();
        ctrl_c.await.expect("Error waiting for the Ctrl-C signal");
    }
}

#[cfg(test)]
mod tests {
    use crate::dispatcher::{Dispatcher, Error::AddListenerExists};
    use crate::listener::Filter;

    #[test]
    fn new_dispatcher() {
        let dispatcher = Dispatcher::new();
        assert_eq!(0, dispatcher.listeners.len());
        assert!(dispatcher.prometheus_metrics_address.is_none());
        assert!(dispatcher.csv_output.is_none());
        assert_eq!(10, dispatcher.report_interval);
    }

    #[test]
    fn add_listener() {
        let mut dispatcher = Dispatcher::new();
        let filter = Filter::new().udp();
        assert_eq!(dispatcher.add_listener("lo", &filter), Ok(()));
        assert_eq!(
            dispatcher.add_listener("lo", &Filter::new()),
            Err(AddListenerExists)
        );
        assert_eq!(dispatcher.add_listener("lo0", &Filter::new()), Ok(()));
        assert_eq!(dispatcher.listeners.len(), 2);
        assert!(dispatcher.listeners.contains_key("lo"));
        assert!(dispatcher.listeners.contains_key("lo0"));
        assert!(!dispatcher.listeners.contains_key("bridge"));
    }
}
