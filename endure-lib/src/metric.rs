//! `metric` is a module implementing a generic mechanism for collecting
//! and exposing metrics in different formats.

use chrono::{DateTime, Local};
use endure_macros::GetMetricValue;
use prometheus_client::encoding::EncodeMetric;
use prometheus_client::{collector::Collector, metrics::gauge::Gauge};
use serde::Serialize;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::{collections::BTreeMap, io, sync::atomic::AtomicI64};

/// A macro formatting metric help.
///
/// The caller must specify two strings. The first should contain a base metrics
/// help text. The second is the metric scope. Depending on this scope, the macro
/// appends a string indicating whether the metric is calculated for all or last N
/// messages.
#[macro_export]
macro_rules! format_help {
    ($h:expr, $s:expr) => {
        match $s {
            MetricScope::Total => format!("{} in all messages.", $h.trim_matches('.')),
            MetricScope::Moving(samples) => {
                format!("{} in last {} messages.", $h.trim_matches('.'), samples)
            }
        }
    };
}

/// Metric scope discriminates the metrics computed from all analyzed
/// packets and the metrics computed using a window of packets.
#[derive(Clone, Debug)]
pub enum MetricScope {
    /// A metric computed from all packets.
    Total,
    /// A metric computed from a window of packets.
    ///
    /// The parameter designates the window size.
    Moving(usize),
}

/// A trait returning a metric value of a given type.
///
/// It is implemented by different concrete types wrapped in the
/// supported metrics. Derive [`endure_macros::GetMetricValue`]
/// to automatically implement getting the values for different
/// metrics types.
///
/// # Generic Type
///
/// It is one of the concrete types in which metrics can be
/// stored (e.g., `i64`, `String` etc.).
///
pub trait GetMetricValue<T> {
    /// Returns the metric value or `None` if the metric has a
    /// a different type.
    fn get_metric_value(&self) -> Option<T>;
}

/// A trait implemented by all auditors collecting metrics in the [`MetricsStore`].
///
/// The [`InitMetrics::init_metrics`] function initializes all auditors' metrics
/// to their default values with the metadata.
pub trait InitMetrics {
    /// Initializes all metrics collected by the auditor in the [`MetricsStore`].
    ///
    /// This function must be invoked for each instantiated auditor before
    /// the `audit` function is invoked for the first time. Failing to do so
    /// will cause panic in the `audit` function due to an attempt to set the
    /// values of the non-existing metrics with the [`MetricsStore::set_metric_value`].
    ///
    fn init_metrics(&self);
}

/// A trait implemented by all auditors collecting metrics in the [`MetricsStore`].
///
/// The [`CollectMetrics::collect_metrics`] function is called by the packet
/// analyzer for each auditor. The auditor writes its metrics into the metrics
/// store.
pub trait CollectMetrics {
    /// Collects metrics from the auditor in the metrics store.
    ///
    /// This function is called by the packet analyzer for each auditor.
    /// The auditor writes its metrics into the metrics store.
    ///
    fn collect_metrics(&self);
}

/// A single metric value having one of the specified types.
#[derive(Clone, Debug, GetMetricValue, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MetricValue {
    /// A 64-bit integer value.
    Int64Value(i64),
    /// A floating point value.
    Float64Value(f64),
    /// A string value.
    StringValue(String),
    /// A timestamp value in local time.
    DateTimeValue(DateTime<Local>),
}

/// An association of a metric name, help text and its value.
///
/// It contains all data required for conversion to the format used
/// by Prometheus.
#[derive(Clone, Debug)]
pub struct Metric {
    /// A metric name.
    name: String,
    /// A metric help describing its purpose.
    help: String,
    /// A metric value.
    value: MetricValue,
}

impl Metric {
    /// Instantiates a new metric.
    ///
    /// # Parameters
    ///
    /// - `name` - metric name.
    /// - `help` - metric help text.
    /// - `value` - metric value.
    ///
    pub fn new(name: &str, help: &str, value: MetricValue) -> Self {
        Metric {
            name: name.to_string(),
            help: help.to_string(),
            value,
        }
    }

    /// Sets a new metric value.
    pub fn set_value(&mut self, value: MetricValue) {
        self.value = value
    }

    /// Returns a metric value.
    ///
    /// # Result
    ///
    /// Returns `None` if the metrics has a non-matching type.
    ///
    pub fn get_value<T>(&self) -> Option<T>
    where
        MetricValue: GetMetricValue<T>,
    {
        self.value.get_metric_value()
    }

    /// Returns an unwrapped existing metric value.
    ///
    /// # Result
    ///
    /// A caller is expected to know and specify a correct type of the metric value.
    /// If a wrong type is specified the function panics indicating a programming
    /// error.
    ///
    pub fn get_value_unwrapped<T>(&self) -> T
    where
        MetricValue: GetMetricValue<T>,
    {
        self.value.get_metric_value().expect(
            "Attempting to get a metric value using wrong type. \
                  It is a programming error. Please report to \
                  https://github.com/msiodelski/endure.",
        )
    }
}

impl Serialize for Metric {
    /// Implementation of the metric serialization to CSV.
    ///
    /// A CSV data row contains only the metrics values. This serializer
    /// extracts the values from the [`Metric`] and leaves off the metric
    /// metadata.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize(serializer)
    }
}

/// A shareable and lockable instance of the [`MetricsStore`].
pub type SharedMetricsStore = Arc<RwLock<MetricsStore>>;

/// A generic storage for metrics.
///
/// It holds named metrics and provides the mechanisms for updating
/// them and serializing into different reporting formats.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MetricsStore {
    include_timestamp: bool,
    header_done: bool,
    metrics: BTreeMap<String, Metric>,
}

impl MetricsStore {
    /// Instantiates a [`MetricsStore`].
    pub fn new() -> Self {
        MetricsStore::default()
    }

    /// Configures the [`MetricsStore`] to include the timestamps.
    ///
    /// The timestamps can be returned in the serialized structures to
    /// indicate when the given set of metrics values have been collected
    /// and output. For example, they are included in each CSV row
    /// marking when the data for this row have been collected.
    pub fn with_timestamp(mut self) -> Self {
        self.include_timestamp = true;
        self
    }

    /// Converts the [`MetricsStore`] to [`SharedMetricsStore`].
    pub fn to_shared(self) -> SharedMetricsStore {
        Arc::new(RwLock::new(self))
    }

    /// Sets new metric or updates an existing metric.
    pub fn set_metric(&mut self, metric: Metric) {
        self.metrics.insert(metric.name.to_string(), metric);
    }

    /// Sets an existing metric's value.
    ///
    /// # Parameters
    ///
    /// - `metric_name` - existing metric name.
    /// - `value` - new metric value.
    ///
    /// # Result
    ///
    /// This function panics if the specified metric doesn't exist. It is
    /// intended to be used in the contexts when the caller is certain that
    /// the metrics has been properly initialized. If it wasn't the function
    /// panics indicating that it is an implementation bug.
    ///
    pub fn set_metric_value(&mut self, metric_name: &str, value: MetricValue) {
        let metric = self.metrics.get_mut(metric_name);
        metric
            .unwrap_or_else(|| {
                panic!(
                    "Attempting to set value for non-existing metrics {:?}. \
                            It is a programming error. Please report to \
                            https://github.com/msiodelski/endure.",
                    value
                )
            })
            .set_value(value);
    }

    /// Returns an existing metric.
    ///
    /// # Result
    ///
    /// It returns `None` when the metric was not found in the store.
    /// Otherwise it returns the metric with its current value.
    pub fn get(&self, metric_name: &str) -> Option<Metric> {
        self.metrics.get(metric_name).cloned()
    }

    /// Returns unwrapped value of the specified metric.
    ///
    /// # Parameters
    ///
    /// - `metric_name` - metric name.
    ///
    /// # Errors
    ///
    /// This function will panic if the metric does not exist or the value
    /// type is not matching. Therefore, this function should mainly be used
    /// in the unit tests, not in the production code.
    ///
    pub fn get_metric_value_unwrapped<T>(&self, metric_name: &str) -> T
    where
        MetricValue: GetMetricValue<T>,
    {
        self.get(metric_name).unwrap().get_value_unwrapped::<T>()
    }

    /// Serializes metric values into a CSV row.
    ///
    /// If [`MetricsStore::with_timestamp`] was called, the timestamps are
    /// included in the first row. The rest of the CSV row is composed from
    /// the existing metrics values. First row is preceded with a CSV header.
    ///
    /// # Parameters
    ///
    /// - `writer` - CSV writer instance (i.e., a file writer or `stdout` writer).
    ///
    /// # Result
    ///
    /// It may return an error when serialization or flushing the writer fails.
    ///
    pub fn serialize_csv<W>(&mut self, writer: &mut csv::Writer<W>) -> io::Result<()>
    where
        W: io::Write,
    {
        if !self.header_done {
            let mut keys: Vec<String> = self.metrics.keys().cloned().collect();
            if self.include_timestamp {
                keys.insert(0, "time".to_string());
            }
            writer.serialize(keys)?;
            self.header_done = true;
        }
        let mut values: Vec<Metric> = self.metrics.values().cloned().collect();
        if self.include_timestamp {
            values.insert(
                0,
                Metric::new("time", "time", MetricValue::DateTimeValue(Local::now())),
            );
        }
        writer.serialize(values)?;
        writer.flush()
    }

    /// Serializes metric values as JSON map.
    ///
    /// # Parameters
    ///
    /// - `writer` - a writer (e.g., [`String`]) where the serialized JSON is written.
    ///
    /// # Result
    ///
    /// It may return an error when writing data to the writer fails.
    ///
    pub fn serialize_json(&self, writer: &mut dyn io::Write) -> Result<(), io::Error> {
        writer
            .write(
                serde_json::to_string(&self.metrics)
                    .unwrap_or_default()
                    .as_bytes(),
            )
            .map(|_| ())?;
        writer.flush()?;
        Ok(())
    }

    /// Serializes metric values as pretty printed JSON map.
    ///
    /// # Parameters
    ///
    /// - `writer` - a writer (e.g., [`String`]) where the serialized JSON is written.
    ///
    /// # Result
    ///
    /// It may return an error when writing data to the writer fails.
    ///
    pub fn serialize_json_pretty(&self, writer: &mut dyn io::Write) -> Result<(), io::Error> {
        writer
            .write(
                serde_json::to_string_pretty(&self.metrics)
                    .unwrap_or_default()
                    .as_bytes(),
            )
            .map(|_| ())?;
        writeln!(writer)?;
        writer.flush()?;
        Ok(())
    }
}

impl Collector for MetricsStore {
    /// Implements encoding the stored metrics into the Prometheus format.
    ///
    /// The [`MetricsStore`] supports a superset of metrics types comparing
    /// to Prometheus. This function selects only the ones that fit the
    /// Prometheus data model (e.g., integer, float) and sets the gauges
    /// for them.
    fn encode(
        &self,
        mut encoder: prometheus_client::encoding::DescriptorEncoder,
    ) -> Result<(), std::fmt::Error> {
        for metric in self.metrics.values() {
            match metric.value {
                MetricValue::Int64Value(value) => {
                    let gauge = Gauge::<i64, AtomicI64>::default();
                    gauge.set(value);
                    let metric_encoder = encoder.encode_descriptor(
                        &metric.name,
                        &metric.help,
                        None,
                        gauge.metric_type(),
                    )?;
                    gauge.encode(metric_encoder)?;
                }
                MetricValue::Float64Value(value) => {
                    let gauge = Gauge::<f64, AtomicU64>::default();
                    gauge.set(value);
                    let metric_encoder = encoder.encode_descriptor(
                        &metric.name,
                        &metric.help,
                        None,
                        gauge.metric_type(),
                    )?;
                    gauge.encode(metric_encoder)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::metric::{GetMetricValue, Metric, MetricScope, MetricValue, MetricsStore};
    use assert_json::assert_json;
    use chrono::{DateTime, Local};
    use csv::WriterBuilder;
    use predicates::prelude::*;

    #[test]
    fn format_help_total() {
        assert_eq!(
            "A help in all messages.",
            format_help!("A help", MetricScope::Total)
        );
    }

    #[test]
    fn metric_set_get_i64_value() {
        let mut metric = Metric::new("i64", "help i64", MetricValue::Int64Value(65));
        assert_eq!("i64", metric.name);
        assert_eq!("help i64", metric.help);
        let metric_value: Option<i64> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert_eq!(65, metric_value.unwrap());
        metric.set_value(MetricValue::Int64Value(10));
        let metric_value: Option<i64> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert_eq!(10, metric_value.unwrap());
        assert_eq!(10, metric.get_value_unwrapped::<i64>());
    }

    #[test]
    fn metric_set_get_f64_value() {
        let mut metric = Metric::new("f64", "help f64", MetricValue::Float64Value(0.1));
        assert_eq!("f64", metric.name);
        assert_eq!("help f64", metric.help);
        let metric_value: Option<f64> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert_eq!(0.1, metric_value.unwrap());
        metric.set_value(MetricValue::Float64Value(0.2));
        let metric_value: Option<f64> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert_eq!(0.2, metric_value.unwrap());
        assert_eq!(0.2, metric.get_value_unwrapped::<f64>());
    }

    #[test]
    fn metric_set_get_string_value() {
        let mut metric = Metric::new(
            "string",
            "help string",
            MetricValue::StringValue("a string".to_string()),
        );
        assert_eq!("string", metric.name);
        assert_eq!("help string", metric.help);
        let metric_value: Option<String> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert_eq!("a string", metric_value.unwrap());
        metric.set_value(MetricValue::StringValue("another".to_string()));
        let metric_value: Option<String> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert_eq!("another", metric_value.unwrap());
        assert_eq!("another", metric.get_value_unwrapped::<String>());
    }

    #[test]
    fn metric_set_get_date_time_string_value() {
        let mut metric = Metric::new(
            "datetime",
            "help datetime",
            MetricValue::DateTimeValue(DateTime::<Local>::default()),
        );
        assert_eq!("datetime", metric.name);
        assert_eq!("help datetime", metric.help);
        let metric_value: Option<DateTime<Local>> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert!(metric_value.unwrap().to_string().starts_with("1970-01-01"));
        assert!(metric
            .get_value_unwrapped::<DateTime<Local>>()
            .to_string()
            .starts_with("1970-01-01"));
        metric.set_value(MetricValue::DateTimeValue(Local::now()));
        let metric_value: Option<DateTime<Local>> = metric.value.get_metric_value();
        assert!(metric_value.is_some());
        assert!(!metric_value.unwrap().to_string().starts_with("1970-01-01"));
    }

    #[test]
    #[should_panic(expected = "Attempting to get a metric value using wrong type. \
                               It is a programming error. Please report to \
                               https://github.com/msiodelski/endure.")]
    fn metric_get_value_unwrapped_wrong_type() {
        let metric = Metric::new("i64", "help i64", MetricValue::Int64Value(65));
        metric.get_value_unwrapped::<f64>();
    }

    #[test]
    fn metrics_store_set_value() {
        let mut store = MetricsStore::new();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(1),
        ));
        let metric = store.get("opcode");
        assert!(metric.is_some());
        store.set_metric_value("opcode", MetricValue::Int64Value(7));
        let metric = store.get("opcode");
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(7, metric.get_value_unwrapped::<i64>());
    }

    #[test]
    #[should_panic(
        expected = "Attempting to set value for non-existing metrics Int64Value(7). \
                               It is a programming error. Please report to \
                               https://github.com/msiodelski/endure."
    )]
    fn metrics_store_set_value_non_existing_metric() {
        let mut store = MetricsStore::new();
        store.set_metric_value("opcode", MetricValue::Int64Value(7));
    }

    #[test]
    fn metrics_store_get_value_unwrapped() {
        let mut store = MetricsStore::new();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(7),
        ));
        assert_eq!(7, store.get_metric_value_unwrapped::<i64>("opcode"));
    }

    #[test]
    #[should_panic]
    fn metrics_store_get_value_unwrapped_invalid_type() {
        let mut store = MetricsStore::new();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(7),
        ));
        store.get_metric_value_unwrapped::<f64>("opcode");
    }

    #[test]
    fn metrics_store_serialize_json() {
        let mut store = MetricsStore::new();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(1),
        ));
        store.set_metric(Metric::new(
            "secs_avg",
            "average secs value",
            MetricValue::Float64Value(0.5),
        ));
        let mut writer = Vec::new();
        let result = store.serialize_json(&mut writer);
        assert!(result.is_ok());
        assert_json!(String::from_utf8(writer.to_vec()).unwrap().as_str(), { "opcode": 1, "secs_avg": 0.5 });
    }

    #[test]
    fn metrics_store_serialize_json_pretty() {
        let mut store = MetricsStore::new();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(1),
        ));
        store.set_metric(Metric::new(
            "secs_avg",
            "average secs value",
            MetricValue::Float64Value(0.5),
        ));
        let mut writer = Vec::new();
        let result = store.serialize_json_pretty(&mut writer);
        assert!(result.is_ok());
        assert_json!(String::from_utf8(writer.to_vec()).unwrap().as_str(), { "opcode": 1, "secs_avg": 0.5 });
    }

    #[test]
    fn metrics_store_serialize_csv_with_timestamp() {
        let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
        let mut store = MetricsStore::new().with_timestamp();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(1),
        ));
        store.set_metric(Metric::new(
            "secs_avg",
            "average secs value",
            MetricValue::Float64Value(0.5),
        ));
        for _ in 0..2 {
            let result = store.serialize_csv(&mut writer);
            assert!(result.is_ok());
        }
        let rows = String::from_utf8(writer.into_inner().unwrap()).unwrap();
        let pred = predicate::str::is_match(
            "time,opcode,secs_avg\n\
                     \\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.+,1,0.5\n\
                     \\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.+,1,0.5",
        )
        .unwrap();
        assert!(pred.eval(rows.as_str()));
    }

    #[test]
    fn metrics_store_serialize_csv_without_timestamp() {
        let mut writer = WriterBuilder::new().has_headers(true).from_writer(vec![]);
        let mut store = MetricsStore::new();
        store.set_metric(Metric::new(
            "opcode",
            "opcode value",
            MetricValue::Int64Value(1),
        ));
        store.set_metric(Metric::new(
            "secs_avg",
            "average secs value",
            MetricValue::Float64Value(0.5),
        ));
        for _ in 0..2 {
            let result = store.serialize_csv(&mut writer);
            assert!(result.is_ok());
        }
        let row = String::from_utf8(writer.into_inner().unwrap()).unwrap();
        assert_eq!("opcode,secs_avg\n1,0.5\n1,0.5\n", row);
    }
}
