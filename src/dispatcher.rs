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
//! to capture DHCPv4 traffic on the `bridge100` interface:
//!
//! ```rust
//! let mut dispatcher = dispatcher::Dispatcher::new();
//! let filter = Filter::new().bootp_server_relay();
//! dispatcher.add_listener("bridge100", filter).expect("listener already added");
//! dispatcher.http_address = Some("127.0.0.1:8080".to_string());
//! dispatcher.enable_prometheus = true;
//! dispatcher.enable_api = true;
//! dispatcher.csv_output = CsvOutputType::File("./csv_metrics.csv")
//! dispatcher.dispatch().await.unwrap();
//! ```

use std::{io::stdout, sync::Arc};

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, Result};
use csv::{Writer, WriterBuilder};
use prometheus_client::{encoding::text::encode, registry::Registry};
use thiserror::Error;
use tokio::{signal, time};

use crate::{
    analyzer::Analyzer,
    auditor::common::AuditProfile,
    sse::{self, Event, EventGateway},
};
use endure_lib::{
    auditor::{AuditConfigContext, SharedAuditConfigContext},
    capture::{self, Inactive, Listener},
    metric::MetricsStore,
};

/// An enum of errors returned by the [`Dispatcher::dispatch`]
#[derive(Debug, Error)]
pub enum DispatchError {
    /// Returned when opening a file writer for CSV reports fails.
    #[error("failed to open the {path:?} file for writing: {details:?}")]
    CsvWriterError {
        /// Path to the file.
        path: String,
        /// Error details.
        details: String,
    },
    /// Returned when starting an HTTP server failed.
    #[error("failed to start an HTTP service: {details:?}")]
    HttpServerError {
        /// Error details.
        details: String,
    },
    /// Returned when starting a traffic capture on an interface failed.
    #[error("starting the traffic capture failed: {details:?}")]
    CaptureError {
        /// Error details.
        details: String,
    },
}

/// An HTTP handler for exposing the metrics to Prometheus.
#[get("/metrics")]
async fn metrics_handler(registry_wrapper: web::Data<RegistryWrapper>) -> Result<HttpResponse> {
    _ = registry_wrapper.analyzer().current_dhcpv4_metrics().await;
    registry_wrapper.http_encode_metrics().await
}

/// An HTTP handler for exposing the metrics via the REST API.
#[get("/api/metrics")]
async fn api_metrics_handler(analyzer: web::Data<Analyzer>) -> Result<HttpResponse> {
    _ = analyzer.current_dhcpv4_metrics().await;
    analyzer.http_encode_to_json().await
}

/// An HTTP handler for exposing server sent events.
#[get("/sse")]
async fn sse_handler(event_gateway: web::Data<EventGateway>) -> impl Responder {
    event_gateway.http_new_client().await
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

/// Wraps [`Registry`] instance and registers a custom collector.
struct RegistryWrapper {
    analyzer: Analyzer,
    registry: Registry,
}

impl RegistryWrapper {
    /// Creates a wrapper instance and registers an [`Analyzer`] as
    /// a custom collector.
    fn new(analyzer: Analyzer) -> Self {
        let mut registry = Registry::default();
        registry.register_collector(Box::new(analyzer.clone()));
        Self { analyzer, registry }
    }

    /// Returns wrapped [`Analyzer`] instance.
    fn analyzer(&self) -> &Analyzer {
        &self.analyzer
    }

    /// HTTP server handler returning collected metrics as a HTTP response.
    ///
    /// This function is directly called from the HTTP server handler for
    /// the `/metrics` endpoint.
    ///
    /// # Errors
    ///
    /// It may return an HTTP 500 status code when encoding the metrics
    /// fails. This, however, is highly unlikely.
    async fn http_encode_metrics(&self) -> Result<HttpResponse> {
        let mut body = String::new();
        match encode(&mut body, &self.registry) {
            Ok(_) => Ok(HttpResponse::Ok()
                .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
                .body(body)),
            Err(_) => Ok(HttpResponse::InternalServerError()
                .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
                .finish()),
        }
    }
}

/// Runs the installed listeners until the stop signal occurs.
pub struct Dispatcher {
    /// A pool of listeners capturing the traffic.
    listener_pool: capture::ListenerPool,

    /// Common event gateway instance receiving events.
    event_gateway: Arc<EventGateway>,

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

    /// Enables server sent events (SSE).
    pub enable_sse: bool,

    /// Shared lockable pointer to the audit configuration.
    pub audit_config_context: SharedAuditConfigContext,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    /// Instantiates the dispatcher.
    ///
    /// It creates an empty map of listeners. The caller should add
    /// the listeners using the [`Dispatcher::add_listener`] function.
    pub fn new() -> Dispatcher {
        Dispatcher {
            listener_pool: capture::ListenerPool::new(),
            event_gateway: Arc::new(EventGateway::new()),
            http_server_address: None,
            csv_output: None,
            report_interval: 0,
            enable_prometheus: false,
            enable_api: false,
            enable_sse: false,
            audit_config_context: AuditConfigContext::new().to_shared(),
        }
    }

    /// Attempts to add a listener for a device.
    ///
    /// The listener is installed for the specific device (i.e., interface).
    /// If there is another listener installed for this device already
    /// it returns [`capture::ListenerAddError::ListenerExists`] error.
    ///
    /// # Arguments
    ///
    /// - `listener` - instance of the listener to be added.
    pub fn add_listener(
        &mut self,
        listener: Listener<Inactive>,
    ) -> Result<(), capture::ListenerAddError> {
        self.listener_pool.add_listener(listener)
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
            let enable_prometheus = self.enable_prometheus;
            let enable_api = self.enable_api;
            let enable_sse = self.enable_sse;
            // Only start the server when the Prometheus, API endpoint or SSE are enabled.
            if !enable_prometheus && !enable_api && !enable_sse {
                return Ok(());
            }
            // Create the prometheus registry and register our analyzer
            // as a metrics collector. The metrics collector encodes the
            // metrics into the format readable by Prometheus
            let registry_wrapper = web::Data::new(RegistryWrapper::new(analyzer.clone()));

            // Analyzer instance is required by the API handler. Let's make
            // it available to the handler.
            let analyzer = web::Data::new(analyzer.clone());

            // Finally, the event gateway is required by the SSE handler.
            let event_gateway = web::Data::from(self.event_gateway.clone());

            // Create HTTP server.
            let server = HttpServer::new(move || {
                let mut app = App::new()
                    .app_data(registry_wrapper.clone())
                    .app_data(analyzer.clone())
                    .app_data(event_gateway.clone());

                // Conditionally enable the Prometheus endpoint.
                if enable_prometheus {
                    app = app.service(metrics_handler);
                }
                // Conditionally enable the REST API.
                if enable_api {
                    app = app.service(api_metrics_handler);
                }
                // Conditionally enable SSE.
                if enable_sse {
                    app = app.service(sse_handler);
                }
                app
            })
            .bind(http_server_address)?
            .run();

            // Run the HTTP server asynchronously.
            tokio::spawn(server);
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
    fn enable_csv_reports<T>(&self, analyzer: Arc<Analyzer>, mut writer: Writer<T>)
    where
        T: std::io::Write + Send + 'static,
    {
        let mut interval = tokio::time::interval(time::Duration::from_secs(self.report_interval));
        let report_future = async move {
            loop {
                interval.tick().await;
                // Write the CSV report into a file or stdout.
                let _ = analyzer
                    .current_dhcpv4_metrics()
                    .await
                    .write()
                    .unwrap()
                    .serialize_csv(&mut writer);

                interval.reset();
            }
        };
        tokio::spawn(report_future);
    }

    /// Enables generation of the periodic metrics report over SSE.
    ///
    /// # Parameters
    ///
    /// - `analyzer` - an analyzer instance providing the metrics for the
    ///   CSV writer.
    fn enable_sse_reports(&self, analyzer: Arc<Analyzer>) {
        let event_gateway = self.event_gateway.clone();
        let mut interval = tokio::time::interval(time::Duration::from_secs(self.report_interval));
        let report_future = async move {
            loop {
                interval.tick().await;
                let metrics_store: MetricsStore = analyzer
                    .current_dhcpv4_metrics()
                    .await
                    .write()
                    .unwrap()
                    .clone();

                // If the SSE is enabled, let's also return the report to the SSE subscribers.
                let event = Event::new(sse::EventType::PeriodicReport)
                    .with_payload(metrics_store)
                    .unwrap();
                let _ = event_gateway.clone().send_event(event).await;

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
    pub async fn dispatch(self) -> Result<(), DispatchError> {
        // Instantiate the analyzer. The analyzer examines the received traffic but
        // it also serves as a Prometheus metrics collector.
        let mut analyzer = Analyzer::create_for_listener(&self.audit_config_context);
        analyzer
            .add_generic_auditors(&AuditProfile::LiveStreamFull)
            .await;
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;

        // Start the HTTP server exporting the metrics to Prometheus if a
        // user has specified the metrics endpoint address.
        let result = self.conditionally_start_http_server(analyzer.clone());
        if result.is_err() {
            return Err(DispatchError::HttpServerError {
                details: result.err().unwrap().to_string(),
            });
        }

        // Check if the user has specified the output location for the CSV reports.
        // In this case, it opens a writer for and runs an asynchronous task writing
        // the periodic reports.
        let analyzer = Arc::new(analyzer);
        if let Some(csv_output) = &self.csv_output {
            match csv_output {
                // Write to stdout.
                CsvOutputType::Stdout => self.enable_csv_reports(
                    analyzer.clone(),
                    WriterBuilder::new()
                        .has_headers(false)
                        .from_writer(stdout()),
                ),
                // Write to a file.
                CsvOutputType::File(csv_output) => {
                    let writer = WriterBuilder::new()
                        .has_headers(false)
                        .from_path(csv_output)
                        .map_err(|err| DispatchError::CsvWriterError {
                            path: csv_output.clone(),
                            details: err.to_string(),
                        })?;
                    self.enable_csv_reports(analyzer.clone(), writer);
                }
            }
        }
        // Check if the user enabled capturing metrics reports over SSE.
        if self.enable_sse {
            self.enable_sse_reports(analyzer.clone());
        }

        // Open a channel to receive the packets captured by the listeners in
        // the threads.
        let mut rx = self
            .listener_pool
            .run()
            .await
            .map_err(|err| DispatchError::CaptureError {
                details: err.to_string(),
            })?;

        // Receive packets from the workers of the channel.
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                analyzer.clone().async_receive(packet).await;
            }
        });

        // Install Ctrl-C signal handler to exit the program when it is pressed.
        let ctrl_c = signal::ctrl_c();
        ctrl_c.await.expect("Error waiting for the Ctrl-C signal");
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use actix_web::body::to_bytes;
    use actix_web::web::Bytes;
    use endure_lib::auditor::AuditConfigContext;

    use crate::analyzer::Analyzer;
    use crate::auditor::common::AuditProfile;
    use crate::dispatcher::DispatchError::{CsvWriterError, HttpServerError};
    use crate::dispatcher::Dispatcher;
    use crate::dispatcher::{CsvOutputType, RegistryWrapper};
    use endure_lib::capture::{self, Filter, Listener};

    trait BodyTest {
        fn as_str(&self) -> &str;
    }

    impl BodyTest for Bytes {
        fn as_str(&self) -> &str {
            std::str::from_utf8(self).unwrap()
        }
    }

    #[test]
    fn new_dispatcher() {
        let dispatcher = Dispatcher::new();
        assert!(dispatcher.http_server_address.is_none());
        assert!(dispatcher.csv_output.is_none());
        assert_eq!(0, dispatcher.report_interval);
    }

    #[test]
    fn add_listener() {
        let mut dispatcher = Dispatcher::new();
        let filter = Filter::new().udp();
        assert!(dispatcher
            .add_listener(Listener::from_iface("lo").with_filter(filter))
            .is_ok());
        assert!(matches!(
            dispatcher
                .add_listener(Listener::from_iface("lo").with_filter(Filter::new()))
                .unwrap_err(),
            capture::ListenerAddError::ListenerExists { .. }
        ));
        assert!(dispatcher
            .add_listener(Listener::from_iface("lo0").with_filter(Filter::new()))
            .is_ok());
    }

    #[tokio::test]
    async fn start_http_server_invalid_address() {
        let mut dispatcher = Dispatcher::new();
        // Set invalid binding address.
        dispatcher.http_server_address = Some("127.0.0.1:".to_string());
        dispatcher.enable_api = true;
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

    #[tokio::test]
    async fn encode_prometheus_metrics() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
        let registry_wrapper = RegistryWrapper::new(analyzer);
        let result = registry_wrapper.http_encode_metrics().await;
        assert!(result.is_ok());
        let body = to_bytes(result.unwrap().into_body()).await.unwrap();
        let body = body.as_str();
        assert!(body.starts_with("# HELP"));
    }
}
