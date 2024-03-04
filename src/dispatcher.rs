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

/// An enum of errors returned by the [`Dispatcher::add_listener`].
#[derive(Debug, PartialEq)]
pub enum ListenerError {
    /// Returned on an attempt to add a duplicate listener.
    ///
    /// There must be at most one listener bound to an interface.
    /// An attempt to bind another listener to the same interface
    /// yields this error. It can be returned by the
    /// [`Dispatcher::add_listener`] function.
    AddListenerExists,
}

/// An enum of errors returned by the [`Dispatcher::dispatch`]
pub enum DispatchError {
    /// Returned when starting an HTTP server failed.
    HttpServerError(std::io::Error),
    /// Returned when opening a file writer for CSV reports fails.
    CsvWriterError(String),
}

/// An HTTP handler for exposing the metrics to Prometheus.
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

/// An HTTP handler for exposing the metrics via the REST API.
///
/// It gathers the metrics from the analyzer and converts it to
/// the JSON format.
///
/// # Parameters
///
/// - `analyzer` - a packet analyzer instance.
async fn api_metrics_handler(analyzer: web::Data<Mutex<Analyzer>>) -> Result<HttpResponse> {
    let report = {
        analyzer.lock().unwrap().current_dhcpv4_report();
    };
    let body = serde_json::to_string(&report).unwrap();
    Ok(HttpResponse::Ok()
        .content_type("application/json")
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

    /// Address and port where HTTP server is bound.
    ///
    /// The same address is used for exporting Prometheus metrics and REST API.
    pub http_server_address: Option<String>,

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

    /// Enables the Prometheus endpoint.
    pub enable_prometheus: bool,

    /// Enables the REST API.
    pub enable_api: bool,
}

impl Dispatcher {
    /// Instantiates the dispatcher.
    ///
    /// It creates an empty map of listeners. The caller should add
    /// the listeners using the [`Dispatcher::add_listener`] function.
    pub fn new() -> Dispatcher {
        Dispatcher {
            listeners: HashMap::new(),
            http_server_address: None,
            csv_output: None,
            report_interval: 10,
            enable_prometheus: false,
            enable_api: false,
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
    pub fn add_listener(
        &mut self,
        interface_name: &str,
        filter: &Filter,
    ) -> Result<(), ListenerError> {
        if self.listeners.contains_key(interface_name) {
            return Err(ListenerError::AddListenerExists);
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
    fn conditionally_start_http_server(&self, analyzer: Analyzer) -> Result<(), std::io::Error> {
        // Check if metrics export to Prometheus should be enabled.
        if let Some(http_server_address) = &self.http_server_address {
            // Only start the server when the Prometheus or API endpoint are enabled.
            let enable_prometheus = self.enable_prometheus;
            let enable_api = self.enable_api;
            if !enable_prometheus && !enable_api {
                return Ok(());
            }
            // Create the prometheus registry and register our analyzer
            // as a metrics collector. The metrics collector encodes the
            // metrics into the format readable by prometheus
            let mut registry = Registry::default();
            registry.register_collector(Box::new(analyzer.clone()));
            let registry = web::Data::new(Mutex::new(registry));
            let analyzer = web::Data::new(Mutex::new(analyzer.clone()));
            // Create HTTP server.
            let server = HttpServer::new(move || {
                let mut app = App::new()
                    .app_data(registry.clone())
                    .app_data(analyzer.clone());
                // Conditionally enable the Prometheus endpoint.
                if enable_prometheus {
                    app = app
                        .service(web::resource("/metrics").route(web::get().to(metrics_handler)));
                }
                // Conditionally enable the REST API.
                if enable_api {
                    app = app.service(
                        web::resource("/api/metrics").route(web::get().to(api_metrics_handler)),
                    );
                }
                app
            })
            .bind(http_server_address)?
            .run();
            // Run the HTTP server asynchronously.
            tokio::spawn(async move { server.await });
            return Ok(());
        }
        Ok(())
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
    pub async fn dispatch(mut self) -> Result<(), DispatchError> {
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
        let result = self.conditionally_start_http_server(analyzer.clone());
        if result.is_err() {
            return Err(DispatchError::HttpServerError(result.err().unwrap()));
        }

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
                CsvOutputType::File(csv_output) => {
                    let writer = WriterBuilder::new().has_headers(true).from_path(csv_output);
                    match writer {
                        Ok(writer) => {
                            self.conditionally_enable_csv_reports(analyzer.clone(), writer)
                        }
                        Err(_) => {
                            return Err(DispatchError::CsvWriterError(
                                writer.err().unwrap().to_string(),
                            ))
                        }
                    }
                }
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::dispatcher::CsvOutputType;
    use crate::dispatcher::DispatchError::{CsvWriterError, HttpServerError};
    use crate::dispatcher::{Dispatcher, ListenerError::AddListenerExists};
    use crate::listener::Filter;

    #[test]
    fn new_dispatcher() {
        let dispatcher = Dispatcher::new();
        assert_eq!(0, dispatcher.listeners.len());
        assert!(dispatcher.http_server_address.is_none());
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

    #[tokio::test]
    async fn start_http_server_invalid_address() {
        let mut dispatcher = Dispatcher::new();
        // Set invalid binding address.
        dispatcher.http_server_address = Some("127.0.0.1:".to_string());
        let result = dispatcher.dispatch().await;
        assert!(matches!(result.unwrap_err(), HttpServerError { .. }));
    }

    #[tokio::test]
    async fn enable_csv_report_invalid_file_path() {
        let mut dispatcher = Dispatcher::new();
        // Set invalid binding address.
        dispatcher.csv_output = Some(CsvOutputType::File(
            "/probablynotexistingdir/file".to_string(),
        ));
        let result = dispatcher.dispatch().await;
        assert!(matches!(result.unwrap_err(), CsvWriterError { .. }));
    }
}
