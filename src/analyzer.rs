//! `analyzer` is a module containing the packet analysis and reporting logic.

use std::sync::Mutex;
use std::{fmt::Debug, sync::Arc};

use endure_lib::capture::{self, PacketWrapper};
use endure_lib::metric::FromMetricsStore;
use endure_lib::metric::{MetricsStore, SharedMetricsStore};
use endure_macros::cond_add_auditor;

use crate::auditor::common::{
    AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor, GenericPacketAuditor,
};
use crate::auditor::opcode::{OpCodeStreamAuditor, OpCodeTotalAuditor};
use crate::auditor::packet_time::PacketTimeAuditor;
use crate::auditor::retransmission::{RetransmissionStreamAuditor, RetransmissionTotalAuditor};
use crate::proto::dhcp::v4;

use actix_web::HttpResponse;
use prometheus_client::collector::Collector;

/// A central instance receiving the captured packets and performing their
/// analysis using available auditors.
///
/// It recognizes received packet types and selects appropriate auditors
/// to perform the analysis.
///
/// # Installing an auditor
///
/// Auditors installed in the [`Analyzer`] must belong to one or more
/// profiles (see [`AuditProfile`]). If the user specifies the profile in
/// the configuration the [`Analyzer`] selects only the auditors matching
/// this profile. Therefore, each auditor must be annotated with the
/// profiles it belongs to using the [`AuditProfileCheck`] macro and
/// the `profile` attribute. The auditors must also derive the
/// [`FromMetricsStore`] trait implementation, so they can be instantiated
/// in the [`Analyzer::add_dhcpv4_auditors`], or other function installing
/// the auditors. Finally, the auditors must be conditionally installed in
/// [`Analyzer::add_dhcpv4_auditors`] or other similar function appropriate
/// for the auditor type.
#[derive(Clone, Debug)]
pub struct Analyzer {
    auditors: Arc<Mutex<AnalyzerAuditorsState>>,
    metrics_store: SharedMetricsStore,
}

#[derive(Debug, Default)]
struct AnalyzerAuditorsState {
    generic_auditors: Vec<Box<dyn GenericPacketAuditor>>,
    dhcpv4_auditors: Vec<Box<dyn DHCPv4PacketAuditor>>,
}

impl Analyzer {
    /// Instantiates the [`Analyzer`] for live capture.
    pub fn create_for_listener() -> Self {
        Self {
            auditors: Arc::new(Mutex::new(AnalyzerAuditorsState::default())),
            metrics_store: MetricsStore::new().with_timestamp().to_shared(),
        }
    }

    /// Instantiates the [`Analyzer`] for capture file.
    pub fn create_for_reader() -> Self {
        Self {
            auditors: Arc::new(Mutex::new(AnalyzerAuditorsState::default())),
            metrics_store: MetricsStore::new().to_shared(),
        }
    }

    /// Installs auditors generic packet auditors for the specified
    /// [`AuditProfile`].
    ///
    /// Generic auditors are not tied to any particular protocol. They typically
    /// analyze the metadata in the received packet's header.
    ///
    /// # Parameters
    ///
    /// - `audit_profile` - auditors belonging to this profile will be enabled.
    ///
    pub fn add_generic_auditors(&mut self, audit_profile: &AuditProfile) {
        let auditors = &mut self.auditors.lock().unwrap().generic_auditors;
        cond_add_auditor!(PacketTimeAuditor);
    }

    /// Installs DHCPv4 packet auditors for the specified [`AuditProfile`].
    ///
    /// # Parameters
    ///
    /// - `audit_profile` - auditors belonging to this profile will be enabled.
    ///
    pub fn add_dhcpv4_auditors(&mut self, audit_profile: &AuditProfile) {
        let auditors = &mut self.auditors.lock().unwrap().dhcpv4_auditors;
        cond_add_auditor!(OpCodeTotalAuditor);
        cond_add_auditor!(OpCodeStreamAuditor);
        cond_add_auditor!(RetransmissionTotalAuditor);
        cond_add_auditor!(RetransmissionStreamAuditor);
    }

    /// Runs analysis of the received packet.
    ///
    /// It checks the packet type and picks appropriate set of auditors
    /// for the analysis.
    ///
    /// # Parameters
    ///
    /// - `packet` - a wrapper containing the captured packet and its metadata
    pub fn receive(&mut self, packet: PacketWrapper) {
        // Run protocol-independent audit.
        self.audit_generic(&packet);

        // Run protocol-specific audit.
        match packet.filter {
            Some(filter) => match filter.get_proto() {
                Some(capture::Proto::Bootp) => {
                    let packet_payload = packet.payload();
                    match packet_payload {
                        Ok(packet_payload) => {
                            let packet_payload = v4::ReceivedPacket::new(&packet_payload);
                            self.audit_dhcpv4(&packet_payload);
                        }
                        // For now we ignore unsupported data links or truncated packets.
                        _ => {}
                    }
                }
                _ => {}
            },
            None => {}
        }
    }

    /// Runs generic auditors for the received packet.
    ///
    /// # Parameters
    ///
    /// - `packet` - a received unparsed packet including metadata.
    ///
    fn audit_generic(&mut self, packet: &PacketWrapper) {
        for auditor in self.auditors.lock().unwrap().generic_auditors.iter_mut() {
            auditor.audit(packet);
        }
    }

    /// Audits a DHCPv4 packet.
    ///
    /// # Parameters
    ///
    /// - `packet` - a received unparsed DHCPv4 packet
    fn audit_dhcpv4(&mut self, packet: &v4::RawPacket) {
        let mut packet = packet.into_parsable();
        for auditor in self.auditors.lock().unwrap().dhcpv4_auditors.iter_mut() {
            auditor.audit(&mut packet);
        }
    }

    /// Collects and teturns the current metrics from all generic and
    /// DHCPv4 auditors.
    ///
    /// # Usage
    ///
    /// Typically, this function is called periodically to make the metrics
    /// available to an external reader (e.g., to append the metrics as a
    /// row of a CSV file or to a Prometheus exporter).
    ///
    pub fn current_dhcpv4_metrics(&self) -> SharedMetricsStore {
        let mut auditors = self.auditors.lock().unwrap();
        for auditor in auditors.generic_auditors.iter_mut() {
            auditor.collect_metrics();
        }
        for auditor in auditors.dhcpv4_auditors.iter_mut() {
            auditor.collect_metrics();
        }
        self.metrics_store.clone()
    }

    /// Returns current metrics in an HTTP response.
    ///
    /// This function is called directly from the HTTP server handler returning
    /// the metrics as a JSON string.
    ///
    /// # Errors
    ///
    /// This function returns no errors.
    pub async fn http_encode_to_json(&self) -> actix_web::Result<HttpResponse> {
        let mut writer = Vec::new();
        let result = self
            .metrics_store
            .read()
            .unwrap()
            .serialize_json_pretty(&mut writer);
        if result.is_err() {
            return Ok(HttpResponse::InternalServerError()
                .content_type("application/json")
                .finish());
        }
        Ok(HttpResponse::Ok()
            .content_type("application/json")
            .body(writer))
    }
}

impl Collector for Analyzer {
    fn encode(
        &self,
        encoder: prometheus_client::encoding::DescriptorEncoder,
    ) -> Result<(), std::fmt::Error> {
        self.current_dhcpv4_metrics()
            .read()
            .unwrap()
            .encode(encoder)
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::AuditProfile;
    use actix_web::{body::to_bytes, web::Bytes};
    use assert_json::assert_json;
    use chrono::{DateTime, Local};
    use pcap::{Linktype, PacketHeader};
    use prometheus_client::{encoding::text::encode, registry::Registry};

    use super::Analyzer;
    use crate::auditor::metric::*;
    use crate::proto::{bootp::*, dhcp::v4::ReceivedPacket, tests::common::TestPacket};

    use endure_lib::capture::{self, PacketWrapper};

    trait BodyTest {
        fn as_str(&self) -> &str;
    }

    impl BodyTest for Bytes {
        fn as_str(&self) -> &str {
            std::str::from_utf8(self).unwrap()
        }
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_ethernet() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        let mut packet_wrapper = PacketWrapper {
            filter: Some(capture::Filter::new().bootp(10067)),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::ETHERNET,
        };
        // The packet is now filled with zeros. Set the first byte of the payload
        // to 1. It makes the packet a BootRequest. If it is successfully audited
        // we should see the metrics to be bumped up.
        packet_wrapper.data[capture::ETHERNET_IP_UDP_HEADER_LENGTH] = 1;
        analyzer.receive(packet_wrapper);

        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100);
        assert!(metric.is_some());
        let metric = metric.unwrap().get_value::<f64>();
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(100.0, metric);
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_loopback() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        let mut packet_wrapper = PacketWrapper {
            filter: Some(capture::Filter::new().bootp(10067)),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::NULL,
        };
        // The packet is now filled with zeros. Set the first byte of the payload
        // to 1. It makes the packet a BootRequest. If it is successfully audited
        // we should see the metrics to be bumped up.
        packet_wrapper.data[capture::LOOPBACK_IP_UDP_HEADER_LENGTH] = 1;
        analyzer.receive(packet_wrapper);

        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100);
        assert!(metric.is_some());
        let metric = metric.unwrap().get_value::<f64>();
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(100.0, metric);
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_non_matching_filter() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        let mut packet_wrapper = PacketWrapper {
            filter: Some(capture::Filter::new().udp()),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::ETHERNET,
        };
        packet_wrapper.data[capture::ETHERNET_IP_UDP_HEADER_LENGTH] = 1;
        analyzer.receive(packet_wrapper);

        // The packet shouldn't be analyzed and the metrics should not
        // be updated.
        let metrics_store = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics_store.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100);
        assert!(metric.is_some());
        assert_eq!(0.0, metric.unwrap().get_value_unwrapped::<f64>())
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_truncated() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        let packet_wrapper = PacketWrapper {
            filter: Some(capture::Filter::new().udp()),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 15],
            data_link: Linktype::ETHERNET,
        };
        analyzer.receive(packet_wrapper);

        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100);
        assert!(metric.is_some());
        assert_eq!(0.0, metric.unwrap().get_value_unwrapped::<f64>())
    }

    #[test]
    fn analyzer_generic_audit() {
        const BASE_TIME: i64 = 1711535347;
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_generic_auditors(&AuditProfile::PcapStreamFull);
        for i in 0..10 {
            let packet = PacketWrapper {
                filter: None,
                header: PacketHeader {
                    ts: libc::timeval {
                        tv_sec: BASE_TIME + i,
                        tv_usec: 0,
                    },
                    caplen: 0,
                    len: 0,
                },
                data: vec![0; 100],
                data_link: Linktype::ETHERNET,
            };
            analyzer.audit_generic(&packet);
        }
        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();

        let packet_wrapper_date_time = metrics.get(METRIC_PACKET_TIME_DATE_TIME);
        assert!(packet_wrapper_date_time.is_some());
        let packet_wrapper_date_time = packet_wrapper_date_time
            .unwrap()
            .get_value_unwrapped::<String>();
        let expected_time =
            DateTime::<Local>::from(DateTime::from_timestamp(BASE_TIME + 9, 0).unwrap());
        assert_eq!(expected_time.to_rfc3339(), packet_wrapper_date_time);
    }

    #[test]
    fn analyzer_audit_dhcpv4() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        for i in 0..10 {
            let test_packet = TestPacket::new_valid_bootp_packet();
            let test_packet = test_packet
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = ReceivedPacket::new(&test_packet.get());
            analyzer.audit_dhcpv4(&packet);
        }
        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();

        let opcode_boot_replies_percent = metrics.get(METRIC_OPCODE_BOOT_REPLIES_PERCENT_100);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            0.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_requests_percent = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            100.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics.get(METRIC_OPCODE_INVALID_PERCENT_100);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_percent = metrics.get(METRIC_RETRANSMIT_PERCENT_100);
        assert!(retransmit_percent.is_some());
        assert_eq!(
            90.0,
            retransmit_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_secs_avg = metrics.get(METRIC_RETRANSMIT_SECS_AVG_100);
        assert!(retransmit_secs_avg.is_some());
        assert_eq!(
            4.5,
            retransmit_secs_avg.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_longest_trying_client =
            metrics.get(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT_100);
        assert!(retransmit_longest_trying_client.is_some());
        assert_eq!(
            "2d:20:59:2b:0c:16",
            retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
        );
    }

    #[test]
    fn encode_to_prometheus() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        let mut registry = Registry::default();
        registry.register_collector(Box::new(analyzer.clone()));
        for i in 0..10 {
            let test_packet = TestPacket::new_valid_bootp_packet();
            let test_packet = test_packet
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = ReceivedPacket::new(&test_packet.get());
            analyzer.audit_dhcpv4(&packet);
        }
        let mut buffer = String::new();
        encode(&mut buffer, &registry).unwrap();
        assert!(buffer.contains(
            "# HELP opcode_boot_requests_count Total number of the BootRequest messages."
        ));
        assert!(buffer
            .contains("# HELP opcode_boot_replies_count Total number of the BootReply messages."));
        assert!(
            buffer.contains("# HELP opcode_invalid_count Total number of the invalid messages.")
        );
        assert!(buffer.contains(
            "# HELP opcode_boot_requests_percent_100 Percentage of the BootRequest messages in last 100 messages."
        ));
        assert!(buffer.contains("# TYPE opcode_boot_requests_percent_100 gauge"));
        assert!(buffer.contains("opcode_boot_requests_percent_100 100.0"));
        assert!(buffer
            .contains("# HELP opcode_boot_replies_percent_100 Percentage of the BootReply messages in last 100 messages."));
        assert!(buffer.contains("# TYPE opcode_boot_replies_percent_100 gauge"));
        assert!(buffer.contains("opcode_boot_replies_percent_100 0.0"));
        assert!(
            buffer.contains("# HELP opcode_invalid_percent_100 Percentage of the invalid messages in last 100 messages.")
        );
        assert!(buffer.contains("# TYPE opcode_invalid_percent_100 gauge"));
        assert!(buffer.contains("opcode_invalid_percent_100 0.0"));
        assert!(buffer.contains("# HELP retransmit_percent_100 Percentage of the retransmissions in the last 100 messages sent by clients."));
        assert!(buffer.contains("# TYPE retransmit_percent_100 gauge"));
        assert!(buffer.contains("retransmit_percent_100 90.0"));
        assert!(buffer.contains("# TYPE retransmit_secs_avg_100 gauge"));
        assert!(buffer.contains("retransmit_secs_avg_100 4.5"));
        assert!(buffer.contains("# EOF"));
    }

    #[tokio::test]
    async fn analyzer_http_encode_to_json() {
        let mut analyzer = Analyzer::create_for_listener();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        let result = analyzer.http_encode_to_json().await;
        assert!(result.is_ok());
        let body = to_bytes(result.unwrap().into_body()).await.unwrap();
        let body = body.as_str();
        assert_json!(body, { METRIC_OPCODE_BOOT_REPLIES_PERCENT_100: 0.0 });
    }
}
