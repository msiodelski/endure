//! `conversation` is a module implementing auditors maintaining the
//! statistics of unicast, broadcast and relayed messages.
//!
//! # Metrics
//!
//! A DHCPv4 server can receive three different types of traffic. When it
//! responds to directly connected clients, it receives broadcast messages.
//! When the clients are connected over a relay, it receives unicast messages
//! sent by one or more relay agents. In both cases it also receives unicast
//! messages from the clients renewing their DHCP leases.
//!
//! Knowing the proportions of these different types of communications can be
//! helpful in diagnosing issues with the server's environment. For example,
//! a server behind a relay should not receive broadcast traffic. Similarly,
//! a directly connected server should not receive relayed traffic.

use std::net::Ipv4Addr;

use super::{
    common::{AuditProfileCheck, DHCPv4PacketAuditor, DHCPv4PacketAuditorWithMetrics},
    util::{FromMetricScope, PercentSMA, Percentage, TotalCounter},
};
use crate::{
    auditor::{common::AuditProfile, metric::*},
    proto::{bootp::OpCode, dhcp::v4},
};
use endure_lib::{
    auditor::{CreateAuditor, SharedAuditConfigContext},
    format_help,
    metric::{CollectMetrics, InitMetrics, Metric, MetricScope, MetricValue, SharedMetricsStore},
};
use endure_macros::{AuditProfileCheck, CreateAuditor, DHCPv4PacketAuditorWithMetrics};
use std::fmt::Debug;

const METRIC_INDEX_BROADCAST: usize = 0;
const METRIC_INDEX_RELAYED: usize = 1;
const METRIC_INDEX_UNICAST: usize = 2;

#[derive(Debug)]
struct ConversationAuditor<MetricTrackingImpl> {
    message_count: MetricTrackingImpl,
}

impl<MetricTrackingImpl> ConversationAuditor<MetricTrackingImpl>
where
    MetricTrackingImpl: FromMetricScope,
{
    pub fn new(metric_scope: MetricScope) -> Self {
        Self {
            message_count: MetricTrackingImpl::from_metric_scope(&metric_scope),
        }
    }
}

impl<MetricTrackingImpl> DHCPv4PacketAuditor for ConversationAuditor<MetricTrackingImpl>
where
    MetricTrackingImpl: Percentage + Debug + Send + Sync,
{
    fn audit(
        &mut self,
        _source_ip_address: &Ipv4Addr,
        dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        let mut packet = packet.write().unwrap();
        // Only consider requests directed to the server. Ignore responses.
        if !packet.opcode().is_ok_and(|op| *op == OpCode::BootRequest) {
            return;
        }
        if packet.giaddr().is_ok_and(|giaddr| !giaddr.is_unspecified()) {
            // If giaddr is not 0.0.0.0, it is a relayed message.
            self.message_count.increase(METRIC_INDEX_RELAYED);
        } else if dest_ip_address.is_broadcast() {
            // Broadcast no-relayed message.
            self.message_count.increase(METRIC_INDEX_BROADCAST);
        } else if !dest_ip_address.is_unspecified() {
            // Unicast no-relayed message.
            self.message_count.increase(METRIC_INDEX_UNICAST);
        }
    }
}

/// An auditor maintaining the total statistics of the unicast, broadcast
/// and relayed messages.
///
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
#[derive(AuditProfileCheck, CreateAuditor, Debug, DHCPv4PacketAuditorWithMetrics)]
#[profiles(AuditProfile::PcapFinalFull)]
pub struct ConversationTotalAuditor {
    metrics_store: SharedMetricsStore,
    auditor: ConversationAuditor<TotalCounter<3>>,
}

impl ConversationTotalAuditor {
    /// Instantiates the auditor.
    ///
    /// # Parameters
    ///
    /// - `metrics_store` is a common instance of the store where metrics are maintained.
    /// - `_config_context` is a pointer to the program configuration.
    ///
    pub fn new(
        metrics_store: &SharedMetricsStore,
        _config_context: &SharedAuditConfigContext,
    ) -> Self {
        Self {
            metrics_store: metrics_store.clone(),
            auditor: ConversationAuditor::new(MetricScope::Total),
        }
    }
}

impl DHCPv4PacketAuditor for ConversationTotalAuditor {
    fn audit(
        &mut self,
        source_ip_address: &Ipv4Addr,
        dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        self.auditor
            .audit(source_ip_address, dest_ip_address, packet);
    }
}

impl CollectMetrics for ConversationTotalAuditor {
    fn collect_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_BROADCAST_COUNT,
            MetricValue::Int64Value(self.auditor.message_count.counter(METRIC_INDEX_BROADCAST)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_RELAYED_COUNT,
            MetricValue::Int64Value(self.auditor.message_count.counter(METRIC_INDEX_RELAYED)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_UNICAST_COUNT,
            MetricValue::Int64Value(self.auditor.message_count.counter(METRIC_INDEX_UNICAST)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .message_count
                    .percentage(METRIC_INDEX_BROADCAST),
            ),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
            MetricValue::Float64Value(self.auditor.message_count.percentage(METRIC_INDEX_RELAYED)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT,
            MetricValue::Float64Value(self.auditor.message_count.percentage(METRIC_INDEX_UNICAST)),
        );
    }
}
impl InitMetrics for ConversationTotalAuditor {
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_BROADCAST_COUNT,
            "Total number of the broadcast messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_RELAYED_COUNT,
            "Total number of the relayed messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_UNICAST_COUNT,
            "Total number of the unicast non-relayed messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT,
            &format_help!("Percentage of the broadcast messages.", MetricScope::Total),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
            &format_help!("Percentage of the relayed messages.", MetricScope::Total),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT,
            &format_help!(
                "Percentage of the unicast non-relayed messages.",
                MetricScope::Total
            ),
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

/// An auditor maintaining the statistics of the unicast, broadcast and
/// relayed messages.
///
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
#[derive(AuditProfileCheck, CreateAuditor, Debug, DHCPv4PacketAuditorWithMetrics)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct ConversationStreamAuditor {
    metric_scope: MetricScope,
    metrics_store: SharedMetricsStore,
    auditor: ConversationAuditor<PercentSMA<3>>,
}

impl ConversationStreamAuditor {
    /// Instantiates the auditor.
    ///
    /// # Parameters
    ///
    /// - `metrics_store` is a common instance of the store where metrics are maintained.
    /// - `config_context` is a pointer to the program configuration.
    ///
    pub fn new(
        metrics_store: &SharedMetricsStore,
        config_context: &SharedAuditConfigContext,
    ) -> Self {
        let sampling_window_size = config_context.read().unwrap().global.sampling_window_size;
        Self {
            metric_scope: MetricScope::Moving(sampling_window_size),
            metrics_store: metrics_store.clone(),
            auditor: ConversationAuditor::new(MetricScope::Moving(sampling_window_size)),
        }
    }
}

impl DHCPv4PacketAuditor for ConversationStreamAuditor {
    fn audit(
        &mut self,
        source_ip_address: &Ipv4Addr,
        dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        self.auditor
            .audit(source_ip_address, dest_ip_address, packet);
    }
}

impl InitMetrics for ConversationStreamAuditor {
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT,
            &format_help!("Percentage of the broadcast messages.", self.metric_scope),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
            &format_help!("Percentage of the relayed messages.", self.metric_scope),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT,
            &format_help!(
                "Percentage of the unicast non-relayed messages.",
                self.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

impl CollectMetrics for ConversationStreamAuditor {
    fn collect_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT,
            MetricValue::Float64Value(self.auditor.message_count.average(0)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
            MetricValue::Float64Value(self.auditor.message_count.average(1)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT,
            MetricValue::Float64Value(self.auditor.message_count.average(2)),
        );
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::net::Ipv4Addr;

    use endure_lib::{
        auditor::{AuditConfigContext, CreateAuditor},
        metric::{CollectMetrics, MetricsStore},
    };

    use crate::{
        auditor::{
            common::{AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor},
            conversation::{ConversationStreamAuditor, ConversationTotalAuditor},
            metric::*,
        },
        proto::{
            bootp::{OpCode, GIADDR_POS},
            dhcp::v4::ReceivedPacket,
            tests::common::TestPacket,
        },
    };

    #[test]
    fn conversation_total_auditor_profiles() {
        assert!(!ConversationTotalAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(!ConversationTotalAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(ConversationTotalAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[rstest]
    #[case(
        // giaddr
        Ipv4Addr::new(192, 168, 1, 1),
        // dest_ip_address
        Ipv4Addr::new(192, 168, 1, 2),
        METRIC_BOOTP_CONVERSATION_RELAYED_COUNT,
        METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
    )]
    #[case(
        // giaddr
        Ipv4Addr::UNSPECIFIED,
        // dest_ip_address
        Ipv4Addr::new(192, 168, 1, 2),
        METRIC_BOOTP_CONVERSATION_UNICAST_COUNT,
        METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT,
    )]
    #[case(
        // giaddr
        Ipv4Addr::new(192, 168, 1, 1),
        // dest_ip_address
        Ipv4Addr::BROADCAST,
        METRIC_BOOTP_CONVERSATION_RELAYED_COUNT,
        METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
    )]
    #[case(
        // giaddr
        Ipv4Addr::UNSPECIFIED,
        // dest_ip_address
        Ipv4Addr::BROADCAST,
        METRIC_BOOTP_CONVERSATION_BROADCAST_COUNT,
        METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT,
    )]
    fn conversation_total_auditor_audit(
        #[case] giaddr: Ipv4Addr,
        #[case] dest_ip_address: Ipv4Addr,
        #[case] expected_count_metric: &str,
        #[case] expected_percent_metric: &str,
    ) {
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor = ConversationTotalAuditor::create_auditor(&metrics_store, &config_context);
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);

        // Simulate receiving a packet with the given giaddr and dest_ip_address combinations.
        let test_packet = TestPacket::new_valid_dhcp_packet().set(GIADDR_POS, &giaddr.octets());
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        auditor.audit(&source_ip_address, &dest_ip_address, packet);
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.read().unwrap();

        // Test the metrics
        assert_eq!(
            1,
            metrics_store_ref.get_metric_value_unwrapped::<i64>(expected_count_metric)
        );
        assert_eq!(
            100.0,
            metrics_store_ref.get_metric_value_unwrapped::<f64>(expected_percent_metric)
        );
    }

    #[rstest]
    #[case(OpCode::BootReply)]
    #[case(OpCode::Invalid(3))]
    fn conversation_total_auditor_not_a_request(#[case] opcode: OpCode) {
        use crate::proto::bootp::OPCODE_POS;

        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor = ConversationTotalAuditor::create_auditor(&metrics_store, &config_context);
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let dest_ip_address = Ipv4Addr::new(192, 168, 1, 2);

        // Set the opcode to the type unsupported by the auditor.
        let test_packet = TestPacket::new_valid_dhcp_packet().set(OPCODE_POS, &[opcode.into()]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();

        // Run the audit.
        auditor.audit(&source_ip_address, &dest_ip_address, packet);
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.read().unwrap();

        // None of the metrics should be incremented.
        assert_eq!(
            0,
            metrics_store_ref
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_CONVERSATION_BROADCAST_COUNT)
        );
        assert_eq!(
            0,
            metrics_store_ref
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_CONVERSATION_RELAYED_COUNT)
        );
        assert_eq!(
            0,
            metrics_store_ref
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_CONVERSATION_UNICAST_COUNT)
        );
    }

    #[test]
    fn conversation_stream_auditor_profiles() {
        assert!(ConversationStreamAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(ConversationStreamAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(!ConversationStreamAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[rstest]
    #[case(
        // giaddr
        Ipv4Addr::new(192, 168, 1, 1),
        // dest_ip_address
        Ipv4Addr::new(192, 168, 1, 2),
        METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
    )]
    #[case(
        // giaddr
        Ipv4Addr::UNSPECIFIED,
        // dest_ip_address
        Ipv4Addr::new(192, 168, 1, 2),
        METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT,
    )]
    #[case(
        // giaddr
        Ipv4Addr::new(192, 168, 1, 1),
        // dest_ip_address
        Ipv4Addr::BROADCAST,
        METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT,
    )]
    #[case(
        // giaddr
        Ipv4Addr::UNSPECIFIED,
        // dest_ip_address
        Ipv4Addr::BROADCAST,
        METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT,
    )]
    fn conversation_stream_auditor_audit(
        #[case] giaddr: Ipv4Addr,
        #[case] dest_ip_address: Ipv4Addr,
        #[case] expected_percent_metric: &str,
    ) {
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor =
            ConversationStreamAuditor::create_auditor(&metrics_store, &config_context);
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);

        // Simulate receiving a packet with the given giaddr and dest_ip_address combinations.
        let test_packet = TestPacket::new_valid_dhcp_packet().set(GIADDR_POS, &giaddr.octets());
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        auditor.audit(&source_ip_address, &dest_ip_address, packet);
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.read().unwrap();

        // Test the moving average metrics.
        assert_eq!(
            100.0,
            metrics_store_ref.get_metric_value_unwrapped::<f64>(expected_percent_metric)
        );
    }
}
