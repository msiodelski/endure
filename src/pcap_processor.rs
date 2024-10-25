//! `pcap_processor` is a module coordinating processing of the
//! `pcap` files and presenting the results.

use std::{
    fs::File,
    io::{self, stdout},
};

use crate::{analyzer::Analyzer, auditor::common::AuditProfile};
use csv::{Writer, WriterBuilder};
use endure_lib::capture::{self, Active, Inactive, Reader, ReaderError};
use thiserror::Error;

/// An enum of errors returned by the [`PcapProcessor::run`]
#[derive(Debug, Error)]
pub enum ProcessorError {
    /// Returned when opening a report file writer fails.
    #[error("failed to open the {path:?} file for writing: {details:?}")]
    FileWriterOpenError {
        /// Path to the file.
        path: String,
        /// Error details.
        details: String,
    },
    /// Returned when writing the report fails.
    #[error("failed to write the report: {details:?}")]
    WriterError {
        /// Error details.
        details: String,
    },
    /// Returns when `pcap` file reader fails.
    #[error("failed to process the pcap file: {path:?}: {details:?}")]
    ReaderError {
        /// Path to the file.
        path: String,
        /// Error details.
        details: String,
    },
}

/// Location of the metrics reports.
#[derive(PartialEq)]
pub enum OutputDest {
    /// Metrics are printed to a console.
    Stdout,
    /// Metrics are printed to a specified file.
    ///
    /// The enum value specifies the file path.
    File(String),
}

/// Supported metrics output format.
#[derive(PartialEq)]
pub enum ReportFormat {
    /// Metrics reported in the CSV format.
    Csv(ReportType),
    /// metrics reported in the JSON format.
    Json,
}

/// CSV report type indicates if the reports are periodic or only final
/// report is presented.
#[derive(PartialEq)]
pub enum ReportType {
    /// Periodic reports are output.
    Stream,
    /// The report is printed after processing the entire file.
    Final,
}

/// [`PcapProcessor`] reads the `pcap` file and outputs the results.
pub struct PcapProcessor {
    /// Location where metrics are written.
    pub output_dest: OutputDest,
    /// Indicates how metrics are reported (e.g., CSV).
    pub report_format: ReportFormat,
    /// Reader instance to be used for parsing the `pcap` file.
    reader: capture::Reader<Inactive>,
}

impl PcapProcessor {
    /// Instantiates the processor.
    ///
    /// The default destination is the `stdout`. The default report format is
    /// a CSV stream.
    ///
    /// # Parameters
    ///
    /// - `reader` - an inactive reader instance associated with a `pcap` file.
    ///
    pub fn from_reader(reader: capture::Reader<Inactive>) -> Self {
        PcapProcessor {
            output_dest: OutputDest::Stdout,
            report_format: ReportFormat::Csv(ReportType::Stream),
            reader,
        }
    }

    /// Reads the capture file and sends the packets to the analyzer.
    ///
    /// # Report Formats
    ///
    /// Depending on the settings, it can output the metrics to a selected
    /// text file or to `stdout`. If the intermediate metrics can only be
    /// output in the CSV format. When JSON format is used only the final
    /// metrics can be output.
    ///
    /// # Errors
    ///
    /// This function may return one of the [`ProcessorError`] variants at
    /// different stages of the capture file processing. Typically It may be
    /// an issue with reading a capture file or writing a report to a file.
    ///
    pub async fn run(self) -> Result<(), ProcessorError> {
        // Reader configuration is independent from the output format, so
        // let's create the reader first.
        let mut reader = self
            .reader
            .start()
            .map_err(|err| ProcessorError::ReaderError {
                path: self.reader.pcap_path(),
                details: err.to_string(),
            })?;

        // Create the analyzer.
        let mut analyzer = Analyzer::create_for_reader();
        match self.report_format {
            ReportFormat::Csv(ReportType::Stream) => {
                analyzer
                    .add_generic_auditors(&AuditProfile::PcapStreamFull)
                    .await;
                analyzer
                    .add_dhcpv4_auditors(&AuditProfile::PcapStreamFull)
                    .await;
            }
            ReportFormat::Json | ReportFormat::Csv(ReportType::Final) => {
                analyzer
                    .add_generic_auditors(&AuditProfile::PcapFinalFull)
                    .await;
                analyzer
                    .add_dhcpv4_auditors(&AuditProfile::PcapFinalFull)
                    .await;
            }
        }

        // Is it stdout or file?
        match self.output_dest {
            OutputDest::Stdout => match self.report_format {
                // Is it CSV or JSON?
                ReportFormat::Csv(report_type) => {
                    let mut writer = WriterBuilder::new()
                        .has_headers(false)
                        .from_writer(stdout());
                    return PcapProcessor::run_with_csv_writer(
                        report_type,
                        &mut analyzer,
                        &mut reader,
                        &mut writer,
                    )
                    .await;
                }
                ReportFormat::Json => {
                    return PcapProcessor::run_with_json_writer(
                        &mut analyzer,
                        &mut reader,
                        &mut stdout(),
                    )
                    .await;
                }
            },
            OutputDest::File(output) => match self.report_format {
                // Is it CSV or JSON?
                ReportFormat::Csv(report_type) => {
                    let mut writer = WriterBuilder::new()
                        .has_headers(false)
                        .from_path(output.clone())
                        .map_err(|err| ProcessorError::FileWriterOpenError {
                            path: output.clone(),
                            details: err.to_string(),
                        })?;
                    return PcapProcessor::run_with_csv_writer(
                        report_type,
                        &mut analyzer,
                        &mut reader,
                        &mut writer,
                    )
                    .await;
                }
                ReportFormat::Json => {
                    let mut writer = File::create(output.clone()).map_err(|err| {
                        ProcessorError::FileWriterOpenError {
                            path: output.clone(),
                            details: err.to_string(),
                        }
                    })?;
                    return PcapProcessor::run_with_json_writer(
                        &mut analyzer,
                        &mut reader,
                        &mut writer,
                    )
                    .await;
                }
            },
        }
    }

    /// Reads the packets from the provided reader, sends to the analysis and
    /// writes the reports in the CSV format.
    ///
    /// # Parameters
    ///
    /// - `report_type` - a report designates whether the intermediate reports
    ///   should be output to a writer or only the final report.
    /// - `analyzer` - an analyzer instance collecting the metrics.
    /// - `reader` - a reader instance associated with a capture file.
    /// - `writer` - a writer instance associated with `stdout` or an output file.
    ///
    async fn run_with_csv_writer<T>(
        report_type: ReportType,
        analyzer: &mut Analyzer,
        reader: &mut Reader<Active>,
        writer: &mut Writer<T>,
    ) -> Result<(), ProcessorError>
    where
        T: std::io::Write + 'static,
    {
        let mut count = 0;
        loop {
            let result = reader.read_next();
            match result {
                Ok(packet) => {
                    if report_type == ReportType::Stream {
                        count += 1;
                    }
                    analyzer.receive(packet).await;
                    // Print the metrics every 100 packets.
                    if count >= 100 {
                        count = 0;
                        analyzer
                            .current_dhcpv4_metrics()
                            .await
                            .write()
                            .unwrap()
                            .serialize_csv(writer)
                            .map_err(|err| ProcessorError::WriterError {
                                details: err.to_string(),
                            })?;
                    }
                }
                Err(ReaderError::Eof {}) => {
                    analyzer
                        .current_dhcpv4_metrics()
                        .await
                        .write()
                        .unwrap()
                        .serialize_csv(writer)
                        .map_err(|err| ProcessorError::WriterError {
                            details: err.to_string(),
                        })?;
                    return Ok(());
                }
                Err(err) => {
                    return Err(ProcessorError::ReaderError {
                        path: reader.pcap_path(),
                        details: err.to_string(),
                    })
                }
            }
        }
    }

    /// Reads the packets from the provided reader, sends to the analysis and
    /// writes the final report in the JSON format.
    ///
    /// # Parameters
    ///
    /// - `analyzer` - an analyzer instance collecting the metrics.
    /// - `reader` - a reader instance associated with a capture file.
    /// - `writer` - a writer instance associated with `stdout` or an output file.
    ///
    async fn run_with_json_writer(
        analyzer: &mut Analyzer,
        reader: &mut Reader<Active>,
        writer: &mut dyn io::Write,
    ) -> Result<(), ProcessorError> {
        loop {
            let result = reader.read_next();
            match result {
                Ok(packet) => {
                    analyzer.receive(packet).await;
                }
                Err(ReaderError::Eof {}) => {
                    analyzer
                        .current_dhcpv4_metrics()
                        .await
                        .read()
                        .unwrap()
                        .serialize_json_pretty(writer)
                        .map_err(|err| ProcessorError::WriterError {
                            details: err.to_string(),
                        })?;
                    return Ok(());
                }
                Err(err) => {
                    return Err(ProcessorError::ReaderError {
                        path: reader.pcap_path(),
                        details: err.to_string(),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, path::PathBuf};

    use endure_lib::capture::Reader;
    use tempdir::TempDir;

    use crate::pcap_processor::{ReportFormat, ReportType};

    use super::{OutputDest, PcapProcessor};

    /// Convenience function returning a path to a test `pcap` file.
    fn resource_path(pcap_name: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/resources/pcap");
        path.push(pcap_name);
        path.as_os_str().to_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn pcap_processor_csv_stream() {
        // Set report location.
        let dir = TempDir::new("test").unwrap();
        let report_path = dir.path().join("reports.csv");
        let report_path_str = report_path.as_os_str().to_str().unwrap().to_owned();

        // Create the reader and the processor.
        let reader = Reader::from_pcap(resource_path("capture000.pcap").as_str());
        let mut processor = PcapProcessor::from_reader(reader);
        processor.output_dest = OutputDest::File(report_path_str);

        // Parse the pcap file.
        let result = processor.run().await;
        assert!(result.is_ok());

        // Make sure the report has been created.
        assert!(report_path.exists());
        let reader = csv::Reader::from_path(report_path);
        assert!(reader.is_ok());
        let mut reader = reader.unwrap();
        assert!(reader.has_headers());

        // In case of the intermediate reports they should contain the time
        // column that holds the last packet time. It is not present if there
        // is only the final report.
        let headers = reader.headers();
        assert!(headers.unwrap().as_slice().contains("time"));
        assert_eq!(1, reader.into_records().count())
    }

    #[tokio::test]
    async fn pcap_processor_csv_final() {
        // Set report location.
        let dir = TempDir::new("test").unwrap();
        let report_path = dir.path().join("reports.csv");
        let report_path_str = report_path.as_os_str().to_str().unwrap().to_owned();

        // Create the reader and the processor.
        let reader = Reader::from_pcap(resource_path("capture000.pcap").as_str());
        let mut processor = PcapProcessor::from_reader(reader);
        processor.output_dest = OutputDest::File(report_path_str);
        processor.report_format = ReportFormat::Csv(ReportType::Final);

        // Parse the pcap file.
        let result = processor.run().await;
        assert!(result.is_ok());

        // Make sure the report has been created.
        assert!(report_path.exists());
        let reader = csv::Reader::from_path(report_path);
        assert!(reader.is_ok());
        let mut reader = reader.unwrap();
        assert!(reader.has_headers());

        // The time column should not be present in the header when only
        // the final report is presented.
        let headers = reader.headers();
        assert!(!headers.unwrap().as_slice().contains("time"));
        assert_eq!(1, reader.into_records().count())
    }

    #[tokio::test]
    async fn pcap_processor_json() {
        // Set report location.
        let dir = TempDir::new("test").unwrap();
        let report_path = dir.path().join("reports.json");
        let report_path_str = report_path.as_os_str().to_str().unwrap().to_owned();

        // Create the reader and the processor.
        let reader = Reader::from_pcap(resource_path("capture000.pcap").as_str());
        let mut processor = PcapProcessor::from_reader(reader);
        processor.output_dest = OutputDest::File(report_path_str.clone());
        processor.report_format = ReportFormat::Json;

        // Parse the pcap file.
        let result = processor.run().await;
        assert!(result.is_ok());

        // Make sure the report has been created.
        assert!(report_path.exists());
        let file = File::open(report_path_str);
        assert!(file.is_ok());

        // Parse JSON report and make sure it is well formatted.
        let mut file = file.unwrap();
        let mut buf = String::new();
        let result = file.read_to_string(&mut buf);
        assert!(result.is_ok());
        let result = serde_json::from_str::<serde_json::Value>(buf.as_str());
        assert!(result.is_ok());
    }
}
