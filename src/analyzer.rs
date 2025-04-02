//! `analyzer` is a module containing the packet analysis and reporting logic.

use endure_lib::{auditor::SharedAuditConfigContext, time_wrapper::TimeWrapper};
use futures::executor::block_on;
use libc::timeval;
use std::{fmt::Debug, net::Ipv4Addr, sync::Arc};
use tokio::sync::RwLock;

use endure_lib::{
    auditor::CreateAuditor,
    capture::{self, PacketWrapper},
    metric::{MetricsStore, SharedMetricsStore},
};
use endure_macros::cond_add_auditor;

use crate::auditor::opcode::{OpCodeStreamAuditor, OpCodeTotalAuditor};
use crate::auditor::packet_time::PacketTimeAuditor;
use crate::auditor::retransmission::{RetransmissionStreamAuditor, RetransmissionTotalAuditor};
use crate::auditor::roundtrip::{DORARoundtripStreamAuditor, DORARoundtripTotalAuditor};
use crate::auditor::{
    common::{AuditProfile, DHCPv4TransactionCache, SharedDHCPv4TransactionCache},
    conversation::{ConversationStreamAuditor, ConversationTotalAuditor},
};
use crate::auditor::{
    common::{
        AuditProfileCheck, DHCPv4PacketAuditorWithMetrics, DHCPv4TransactionAuditorWithMetrics,
        GenericPacketAuditorWithMetrics,
    },
    spectrum::{DHCPv4SpectrumStreamAuditor, DHCPv4SpectrumTotalAuditor},
};
use crate::proto::dhcp::v4::{self};

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
/// [`CreateAuditor`] trait implementation, so they can be instantiated
/// in the [`Analyzer::add_dhcpv4_auditors`], or other function installing
/// the auditors. Finally, the auditors must be conditionally installed in
/// [`Analyzer::add_dhcpv4_auditors`] or other similar function appropriate
/// for the auditor type.
#[derive(Clone, Debug)]
pub struct Analyzer {
    state: Arc<RwLock<AnalyzerState>>,
}

impl Analyzer {
    /// Instantiates the [`Analyzer`] for live capture.
    ///
    /// # Parameters
    ///
    /// - `audit_config_context` is a pointer to the configuration of the auditors.
    ///
    pub fn create_for_listener(audit_config_context: &SharedAuditConfigContext) -> Self {
        Self {
            state: Arc::new(RwLock::new(AnalyzerState::create_for_listener(
                audit_config_context,
            ))),
        }
    }

    /// Instantiates the [`Analyzer`] for capture file.
    ///
    /// - `audit_config_context` is a pointer to the configuration of the auditors.
    ///
    pub fn create_for_reader(audit_config_context: &SharedAuditConfigContext) -> Self {
        Self {
            state: Arc::new(RwLock::new(AnalyzerState::create_for_reader(
                audit_config_context,
            ))),
        }
    }

    /// Installs generic packet auditors for the specified [`AuditProfile`].
    ///
    /// Generic auditors are not tied to any particular protocol. They typically
    /// analyze the metadata in the received packet's header.
    ///
    /// # Parameters
    ///
    /// - `audit_profile` - auditors belonging to this profile will be enabled.
    ///
    pub async fn add_generic_auditors(&mut self, audit_profile: &AuditProfile) {
        self.state.write().await.add_generic_auditors(audit_profile);
    }

    /// Installs DHCPv4 packet auditors for the specified [`AuditProfile`].
    ///
    /// # Parameters
    ///
    /// - `audit_profile` - auditors belonging to this profile will be enabled.
    ///
    pub async fn add_dhcpv4_auditors(&mut self, audit_profile: &AuditProfile) {
        self.state.write().await.add_dhcpv4_auditors(audit_profile);
    }

    /// Runs analysis of the received packet.
    ///
    /// It checks the packet type and picks appropriate set of auditors
    /// for the analysis.
    ///
    /// # Parameters
    ///
    /// - `packet` - a wrapper containing the captured packet and its metadata
    pub async fn receive(&self, packet: PacketWrapper) {
        self.state.read().await.receive(packet).await;
    }

    /// Runs analysis of the received packet asynchronously.
    ///
    /// It checks the packet type and picks appropriate set of auditors
    /// for the analysis.
    ///
    /// # Parameters
    ///
    /// - `packet` - a wrapper containing the captured packet and its metadata
    pub async fn async_receive(&self, packet: PacketWrapper) {
        let state = self.state.clone();
        tokio::spawn(async move {
            state.read().await.receive(packet).await;
        });
    }

    /// Collects and returns the current metrics from all generic and
    /// DHCPv4 auditors.
    ///
    /// # Usage
    ///
    /// Typically, this function is called periodically to make the metrics
    /// available to an external reader (e.g., to append the metrics as a
    /// row of a CSV file or to a Prometheus exporter).
    ///
    pub async fn current_dhcpv4_metrics(&self) -> SharedMetricsStore {
        self.state.read().await.current_dhcpv4_metrics().await
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
            .state
            .read()
            .await
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

#[derive(Clone, Debug)]
struct AnalyzerState {
    generic_auditors: Vec<Arc<RwLock<Box<dyn GenericPacketAuditorWithMetrics>>>>,
    dhcpv4_auditors: Vec<Arc<RwLock<Box<dyn DHCPv4PacketAuditorWithMetrics>>>>,
    dhcpv4_transactional_auditors: Vec<Arc<RwLock<Box<dyn DHCPv4TransactionAuditorWithMetrics>>>>,
    dhcpv4_transactions: SharedDHCPv4TransactionCache,
    metrics_store: SharedMetricsStore,
    audit_config_context: SharedAuditConfigContext,
}

impl AnalyzerState {
    /// Instantiates the [`Analyzer`] for live capture.
    ///
    /// # Parameters
    ///
    /// - `audit_config_context` is a pointer to the configuration of the auditors.
    ///
    pub fn create_for_listener(audit_config_context: &SharedAuditConfigContext) -> Self {
        Self {
            generic_auditors: Vec::default(),
            dhcpv4_auditors: Vec::default(),
            dhcpv4_transactional_auditors: Vec::default(),
            dhcpv4_transactions: DHCPv4TransactionCache::default().to_shared(),
            metrics_store: MetricsStore::new().with_timestamp().to_shared(),
            audit_config_context: audit_config_context.clone(),
        }
    }

    /// Instantiates the [`Analyzer`] for capture file.
    ///
    /// # Parameters
    ///
    /// - `audit_config_context` is a pointer to the configuration of the auditors.
    ///
    pub fn create_for_reader(audit_config_context: &SharedAuditConfigContext) -> Self {
        Self {
            generic_auditors: Vec::default(),
            dhcpv4_auditors: Vec::default(),
            dhcpv4_transactional_auditors: Vec::default(),
            dhcpv4_transactions: DHCPv4TransactionCache::default().to_shared(),
            metrics_store: MetricsStore::new().to_shared(),
            audit_config_context: audit_config_context.clone(),
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
        let auditors = &mut self.generic_auditors;
        cond_add_auditor!(PacketTimeAuditor);
    }

    /// Installs DHCPv4 packet auditors for the specified [`AuditProfile`].
    ///
    /// # Parameters
    ///
    /// - `audit_profile` - auditors belonging to this profile will be enabled.
    ///
    pub fn add_dhcpv4_auditors(&mut self, audit_profile: &AuditProfile) {
        let auditors = &mut self.dhcpv4_auditors;
        cond_add_auditor!(OpCodeTotalAuditor);
        cond_add_auditor!(OpCodeStreamAuditor);
        cond_add_auditor!(RetransmissionTotalAuditor);
        cond_add_auditor!(RetransmissionStreamAuditor);
        cond_add_auditor!(ConversationTotalAuditor);
        cond_add_auditor!(ConversationStreamAuditor);

        let auditors = &mut self.dhcpv4_transactional_auditors;
        cond_add_auditor!(DORARoundtripTotalAuditor);
        cond_add_auditor!(DORARoundtripStreamAuditor);
        cond_add_auditor!(DHCPv4SpectrumTotalAuditor);
        cond_add_auditor!(DHCPv4SpectrumStreamAuditor);
    }

    /// Runs generic auditors for the received packet.
    ///
    /// # Parameters
    ///
    /// - `packet` - a received unparsed packet including metadata.
    ///
    async fn audit_generic(&self, packet: &PacketWrapper) {
        for auditor in self.generic_auditors.iter() {
            auditor.write().await.audit(packet);
        }
    }

    /// Audits a DHCPv4 packet.
    ///
    /// # Parameters
    ///
    /// - `packet_time` - a timestamp of the received packet.
    /// - `src_ip_address` - an IP address of the source of the packet.
    /// - `dest_ip_address` - an IP address of the destination of the packet.
    /// - `packet` - a received unparsed DHCPv4 packet
    async fn audit_dhcpv4(
        &self,
        packet_time: timeval,
        src_ip_address: &Ipv4Addr,
        dest_ip_address: &Ipv4Addr,
        packet: &v4::RawPacket,
    ) {
        let mut packet = packet.into_shared_parsable();
        if let Ok(transaction) = self
            .dhcpv4_transactions
            .write()
            .await
            .insert(TimeWrapper::from_timeval(packet_time, packet.clone()))
        {
            for auditor in self.dhcpv4_transactional_auditors.iter() {
                auditor.write().await.audit(&mut transaction.clone());
            }
        }
        let dhcpv4_transactions = self.dhcpv4_transactions.clone();
        tokio::spawn(async move {
            dhcpv4_transactions
                .write()
                .await
                .garbage_collect_expired(10)
                .await;
        });
        for auditor in self.dhcpv4_auditors.iter() {
            auditor
                .write()
                .await
                .audit(src_ip_address, dest_ip_address, &mut packet);
        }
    }

    /// Runs analysis of the received packet.
    ///
    /// It checks the packet type and picks appropriate set of auditors
    /// for the analysis.
    ///
    /// # Parameters
    ///
    /// - `packet` - a wrapper containing the captured packet and its metadata
    pub async fn receive(&self, packet: PacketWrapper) {
        // Run protocol-independent audit.
        self.audit_generic(&packet).await;

        // Run protocol-specific audit.
        if let Some(filter) = packet.filter {
            if let Some(capture::Proto::Bootp) = filter.get_proto() {
                let packet_payload = packet.payload();
                if let Ok(packet_payload) = packet_payload {
                    let packet_payload = v4::ReceivedPacket::new(packet_payload);
                    self.audit_dhcpv4(
                        packet.header.ts,
                        &packet.ipv4_source_address().unwrap(),
                        &packet.ipv4_destination_address().unwrap(),
                        &packet_payload,
                    )
                    .await;
                }
            }
        }
    }

    /// Collects and returns the current metrics from all generic and
    /// DHCPv4 auditors.
    ///
    /// # Usage
    ///
    /// Typically, this function is called periodically to make the metrics
    /// available to an external reader (e.g., to append the metrics as a
    /// row of a CSV file or to a Prometheus exporter).
    ///
    pub async fn current_dhcpv4_metrics(&self) -> SharedMetricsStore {
        for auditor in self.generic_auditors.iter() {
            auditor.write().await.collect_metrics();
        }
        for auditor in self.dhcpv4_auditors.iter() {
            auditor.write().await.collect_metrics();
        }
        for auditor in self.dhcpv4_transactional_auditors.iter() {
            auditor.write().await.collect_metrics();
        }
        self.metrics_store.clone()
    }
}

impl Collector for Analyzer {
    fn encode(
        &self,
        encoder: prometheus_client::encoding::DescriptorEncoder,
    ) -> Result<(), std::fmt::Error> {
        block_on(self.current_dhcpv4_metrics())
            .read()
            .unwrap()
            .encode(encoder)
    }
}

#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;

    use crate::analyzer::{AnalyzerState, AuditProfile};
    use actix_web::{body::to_bytes, web::Bytes};
    use assert_json::assert_json;
    use chrono::{DateTime, Local};
    use endure_lib::auditor::AuditConfigContext;
    use libc::timeval;
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

    #[tokio::test]
    async fn analyzer_receive_dhcp4_packet_ethernet() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
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
        analyzer.receive(packet_wrapper).await;

        let metrics = analyzer
            .current_dhcpv4_metrics()
            .await
            .read()
            .unwrap()
            .clone();
        let metric = metrics.get(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        let metric = metric.unwrap().get_value::<f64>();
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(100.0, metric);
    }

    #[tokio::test]
    async fn analyzer_receive_dhcp4_packet_loopback() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
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
        analyzer.receive(packet_wrapper).await;

        let metrics = analyzer
            .current_dhcpv4_metrics()
            .await
            .read()
            .unwrap()
            .clone();
        let metric = metrics.get(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        let metric = metric.unwrap().get_value::<f64>();
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(100.0, metric);
    }

    #[tokio::test]
    async fn analyzer_receive_dhcp4_packet_non_matching_filter() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
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
        analyzer.receive(packet_wrapper).await;

        // The packet shouldn't be analyzed and the metrics should not
        // be updated.
        let metrics_store = analyzer
            .current_dhcpv4_metrics()
            .await
            .read()
            .unwrap()
            .clone();
        let metric = metrics_store.get(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        assert_eq!(0.0, metric.unwrap().get_value_unwrapped::<f64>())
    }

    #[tokio::test]
    async fn analyzer_receive_dhcp4_packet_truncated() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
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
        analyzer.receive(packet_wrapper).await;

        let metrics = analyzer
            .current_dhcpv4_metrics()
            .await
            .read()
            .unwrap()
            .clone();
        let metric = metrics.get(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        assert_eq!(0.0, metric.unwrap().get_value_unwrapped::<f64>())
    }

    #[tokio::test]
    async fn analyzer_generic_audit() {
        const BASE_TIME: i64 = 1711535347;
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = AnalyzerState::create_for_listener(&audit_config_context);
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
            analyzer.audit_generic(&packet).await;
        }
        let metrics = analyzer
            .current_dhcpv4_metrics()
            .await
            .read()
            .unwrap()
            .clone();

        let packet_wrapper_date_time = metrics.get(METRIC_PACKET_TIME_DATE_TIME);
        assert!(packet_wrapper_date_time.is_some());
        let packet_wrapper_date_time = packet_wrapper_date_time
            .unwrap()
            .get_value_unwrapped::<String>();
        let expected_time =
            DateTime::<Local>::from(DateTime::from_timestamp(BASE_TIME + 9, 0).unwrap());
        assert_eq!(expected_time.to_rfc3339(), packet_wrapper_date_time);
    }

    #[tokio::test]
    async fn analyzer_audit_dhcpv4() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = AnalyzerState::create_for_listener(&audit_config_context);
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamFull);
        for i in 0..10 {
            let test_packet = TestPacket::new_valid_bootp_packet();
            let test_packet = test_packet
                .set(OPCODE_POS, &[OpCode::BootRequest.into()])
                .set(SECS_POS, &[0, i]);
            let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
            let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
            let packet = ReceivedPacket::new(test_packet.get());
            analyzer
                .audit_dhcpv4(
                    timeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    },
                    &source_ip_address,
                    &destination_ip_address,
                    &packet,
                )
                .await;
        }
        let metrics = analyzer
            .current_dhcpv4_metrics()
            .await
            .read()
            .unwrap()
            .clone();

        let opcode_boot_replies_percent = metrics.get(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            0.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_requests_percent = metrics.get(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            100.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics.get(METRIC_BOOTP_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let bootp_retransmit_percent = metrics.get(METRIC_BOOTP_RETRANSMIT_PERCENT);
        assert!(bootp_retransmit_percent.is_some());
        assert_eq!(
            90.0,
            bootp_retransmit_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let bootp_retransmit_secs_avg = metrics.get(METRIC_BOOTP_RETRANSMIT_SECS_AVG);
        assert!(bootp_retransmit_secs_avg.is_some());
        assert_eq!(
            4.5,
            bootp_retransmit_secs_avg
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let bootp_retransmit_longest_trying_client =
            metrics.get(METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT);
        assert!(bootp_retransmit_longest_trying_client.is_some());
        assert_eq!(
            "2d:20:59:2b:0c:16",
            bootp_retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
        );
    }

    #[tokio::test]
    async fn encode_to_prometheus() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
        let mut registry = Registry::default();
        registry.register_collector(Box::new(analyzer.clone()));
        for i in 0..10 {
            let test_packet = TestPacket::new_valid_bootp_packet();
            let test_packet = test_packet.set(OPCODE_POS, &[1]).set(SECS_POS, &[0, i]);
            let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
            let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
            let packet = ReceivedPacket::new(test_packet.get());
            analyzer
                .state
                .read()
                .await
                .audit_dhcpv4(
                    timeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    },
                    &source_ip_address,
                    &destination_ip_address,
                    &packet,
                )
                .await;
        }
        let mut buffer = String::new();
        encode(&mut buffer, &registry).unwrap();
        assert!(buffer.contains(
            "# HELP bootp_opcode_boot_requests_count Total number of the BootRequest messages."
        ));
        assert!(buffer.contains(
            "# HELP bootp_opcode_boot_replies_count Total number of the BootReply messages."
        ));
        assert!(buffer
            .contains("# HELP bootp_opcode_invalid_count Total number of the invalid messages."));
        assert!(buffer.contains(
            "# HELP bootp_opcode_boot_requests_percent Percentage of the BootRequest messages in last 100 messages."
        ));
        assert!(buffer.contains("# TYPE bootp_opcode_boot_requests_percent gauge"));
        assert!(buffer.contains("opcode_boot_requests_percent 100.0"));
        assert!(buffer
            .contains("# HELP bootp_opcode_boot_replies_percent Percentage of the BootReply messages in last 100 messages."));
        assert!(buffer.contains("# TYPE bootp_opcode_boot_replies_percent gauge"));
        assert!(buffer.contains("opcode_boot_replies_percent 0.0"));
        assert!(
            buffer.contains("# HELP bootp_opcode_invalid_percent Percentage of the invalid messages in last 100 messages.")
        );
        assert!(buffer.contains("# TYPE bootp_opcode_invalid_percent gauge"));
        assert!(buffer.contains("bootp_opcode_invalid_percent 0.0"));
        assert!(buffer.contains("# HELP bootp_retransmit_percent Percentage of the retransmissions in last 100 messages."));
        assert!(buffer.contains("# TYPE bootp_retransmit_percent gauge"));
        assert!(buffer.contains("bootp_retransmit_percent 90.0"));
        assert!(buffer.contains("# TYPE bootp_retransmit_secs_avg gauge"));
        assert!(buffer.contains("bootp_retransmit_secs_avg 4.5"));
        assert!(buffer.contains("# EOF"));
    }

    #[tokio::test]
    async fn analyzer_http_encode_to_json() {
        let audit_config_context = AuditConfigContext::new().to_shared();
        let mut analyzer = Analyzer::create_for_listener(&audit_config_context);
        analyzer
            .add_dhcpv4_auditors(&AuditProfile::LiveStreamFull)
            .await;
        let result = analyzer.http_encode_to_json().await;
        assert!(result.is_ok());
        let body = to_bytes(result.unwrap().into_body()).await.unwrap();
        let body = body.as_str();
        assert_json!(body, { METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT: 0.0 });
    }
}
