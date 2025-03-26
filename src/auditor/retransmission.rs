//! `retransmission` is a module implementing auditors maintaining the
//! statistics of DHCP retransmissions.
//!
//! The auditors look into the `secs` field of the `BOOTP` messages. If its
//! value is greater than zero it indicates that the client has been unable
//! to allocate a lease in the previous attempts and the client retransmits.
//!
//! # Metrics
//!
//! Client retransmissions often occur when the server is unable to keep up
//! with the DHCP traffic load. A high average value of the `secs` field and
//! a high average number of retransmissions indicate that the server has
//! hard time to keep up with the traffic.
//!
//! The auditors also keep track of the MAC address of the client who has been
//! trying to get a lease for a longest period of time packets.

use super::{
    common::{
        AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor, DHCPv4PacketAuditorWithMetrics,
    },
    util::{Average, FromMetricScope, MovingRanks, RoundedSMA, RoundedSTA},
};
use crate::auditor::metric::*;
use crate::proto::{bootp::OpCode, dhcp::v4};
use endure_lib::{
    auditor::{CreateAuditor, SharedAuditConfigContext},
    format_help,
    metric::{CollectMetrics, InitMetrics, Metric, MetricScope, MetricValue, SharedMetricsStore},
};
use endure_macros::{AuditProfileCheck, CreateAuditor, DHCPv4PacketAuditorWithMetrics};
use std::{fmt::Debug, net::Ipv4Addr};

#[derive(Debug)]
struct RetransmissionAuditor<AverageImpl> {
    metric_scope: MetricScope,
    metrics_store: SharedMetricsStore,
    retransmits: AverageImpl,
    secs: AverageImpl,
    longest_trying_client: MovingRanks<String, u16, 1>,
}

impl<AverageImpl> RetransmissionAuditor<AverageImpl>
where
    AverageImpl: FromMetricScope,
{
    pub fn new(metrics_store: &SharedMetricsStore, metric_scope: MetricScope) -> Self {
        Self {
            metrics_store: metrics_store.clone(),
            retransmits: AverageImpl::from_metric_scope(&metric_scope),
            secs: AverageImpl::from_metric_scope(&metric_scope),
            longest_trying_client: MovingRanks::new(usize::MAX),
            metric_scope,
        }
    }
}

impl<AverageImpl> DHCPv4PacketAuditor for RetransmissionAuditor<AverageImpl>
where
    AverageImpl: Average + Debug + Send + Sync,
{
    fn audit(
        &mut self,
        _source_ip_address: &Ipv4Addr,
        _dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        let mut packet = packet.write().unwrap();
        let opcode = packet.opcode();
        if opcode.is_err() || opcode.is_ok() && opcode.unwrap().ne(&OpCode::BootRequest) {
            return;
        }
        match packet.secs() {
            Ok(secs) => {
                if secs > 0 {
                    // Since we want the percentage rather than the average between 0 and 1,
                    // let's add 100 (instead of 1), so we get appropriate precision and we
                    // don't have to multiply the resulting average by 100 later on.
                    self.retransmits.add_sample(100u64);
                    // Get the client's hardware address.
                    match packet.chaddr() {
                        Ok(haddr) => {
                            self.longest_trying_client
                                .add_score(haddr.to_string(), secs);
                        }
                        Err(_) => {}
                    }
                } else {
                    self.retransmits.add_sample(0u64);
                }
                self.secs.add_sample(secs as u64);
            }
            Err(_) => {}
        };
    }
}

impl<AverageImpl> InitMetrics for RetransmissionAuditor<AverageImpl>
where
    AverageImpl: Average + Sync,
{
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_RETRANSMIT_PERCENT,
            &format_help!("Percentage of the retransmissions.", self.metric_scope),
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_RETRANSMIT_SECS_AVG,
            &format_help!("Average retransmission time.", self.metric_scope),
            MetricValue::Float64Value(self.secs.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT,
            &format_help!(
                "MAC address of the the client who has been trying the longest to acquire a lease.",
                self.metric_scope
            ),
            MetricValue::StringValue("".to_string()),
        ));
    }
}

impl<AverageImpl> CollectMetrics for RetransmissionAuditor<AverageImpl>
where
    AverageImpl: Average + Debug + Send + Sync,
{
    fn collect_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_BOOTP_RETRANSMIT_PERCENT,
            MetricValue::Float64Value(self.retransmits.average()),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_RETRANSMIT_SECS_AVG,
            MetricValue::Float64Value(self.secs.average()),
        );

        if let Some(longest_trying_client) = self.longest_trying_client.get_rank(0) {
            metrics_store.set_metric_value(
                METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT,
                MetricValue::StringValue(longest_trying_client.id.clone()),
            );
        }
    }
}

/// An auditor maintaining the statistics of DHCP retransmissions in all messages.
///
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
///
#[derive(AuditProfileCheck, CreateAuditor, Debug, DHCPv4PacketAuditorWithMetrics)]
#[profiles(AuditProfile::PcapFinalFull)]
pub struct RetransmissionTotalAuditor {
    auditor: RetransmissionAuditor<RoundedSTA<10>>,
}

impl RetransmissionTotalAuditor {
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
            auditor: RetransmissionAuditor::new(metrics_store, MetricScope::Total),
        }
    }
}

impl DHCPv4PacketAuditor for RetransmissionTotalAuditor {
    fn audit(
        &mut self,
        _source_ip_address: &Ipv4Addr,
        _dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        self.auditor
            .audit(_source_ip_address, _dest_ip_address, packet)
    }
}

impl InitMetrics for RetransmissionTotalAuditor {
    fn init_metrics(&self) {
        self.auditor.init_metrics()
    }
}

impl CollectMetrics for RetransmissionTotalAuditor {
    fn collect_metrics(&self) {
        self.auditor.collect_metrics()
    }
}

/// An auditor maintaining the statistics of DHCP retransmissions.
///
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
///
#[derive(AuditProfileCheck, CreateAuditor, Debug, DHCPv4PacketAuditorWithMetrics)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct RetransmissionStreamAuditor {
    auditor: RetransmissionAuditor<RoundedSMA<10>>,
}

impl RetransmissionStreamAuditor {
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
        Self {
            auditor: RetransmissionAuditor::new(
                metrics_store,
                MetricScope::Moving(config_context.read().unwrap().global.sampling_window_size),
            ),
        }
    }
}

impl DHCPv4PacketAuditor for RetransmissionStreamAuditor {
    fn audit(
        &mut self,
        source_ip_address: &Ipv4Addr,
        dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        self.auditor
            .audit(source_ip_address, dest_ip_address, packet)
    }
}

impl InitMetrics for RetransmissionStreamAuditor {
    fn init_metrics(&self) {
        self.auditor.init_metrics()
    }
}

impl CollectMetrics for RetransmissionStreamAuditor {
    fn collect_metrics(&self) {
        self.auditor.collect_metrics()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use endure_lib::{
        auditor::{AuditConfigContext, CreateAuditor},
        metric::{CollectMetrics, MetricsStore},
    };

    use crate::{
        auditor::{
            common::{AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor},
            metric::*,
            retransmission::{RetransmissionStreamAuditor, RetransmissionTotalAuditor},
        },
        proto::{
            bootp::{OpCode, OPCODE_POS, SECS_POS},
            dhcp::v4::ReceivedPacket,
            tests::common::TestPacket,
        },
    };

    #[test]
    fn retransmissions_total_auditor_profiles() {
        assert!(!RetransmissionTotalAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(!RetransmissionTotalAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(RetransmissionTotalAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[test]
    fn retransmissions_total_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor =
            RetransmissionTotalAuditor::create_auditor(&metrics_store, &config_context);
        let test_packet = TestPacket::new_valid_bootp_packet();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![OpCode::BootRequest.into()])
            .set(SECS_POS, &vec![0, 0]);

        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        auditor.audit(
            &source_ip_address,
            &destination_ip_address,
            &mut ReceivedPacket::new(test_packet.get()).into(),
        );
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_SECS_AVG)
        );

        assert_eq!(
            "",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(
                    METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT
                )
        );

        // Audit 4 packets. The first is not a retransmission. The remaining ones
        // have the increasing secs value.
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        for i in 0..4 {
            let test_packet = TestPacket::new_valid_bootp_packet()
                .set(OPCODE_POS, &vec![OpCode::BootRequest.into()])
                .set(SECS_POS, &vec![0, i]);
            auditor.audit(
                &source_ip_address,
                &destination_ip_address,
                &mut ReceivedPacket::new(&test_packet.get()).into(),
            );
        }
        // 60% of packets were retransmissions. The average secs field value was 1.2.
        auditor.collect_metrics();

        assert_eq!(
            60.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_PERCENT)
        );

        assert_eq!(
            1.2,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_SECS_AVG)
        );

        assert_eq!(
            "2d:20:59:2b:0c:16",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(
                    METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT
                )
        );
    }

    #[test]
    fn retransmissions_stream_auditor_profiles() {
        assert!(RetransmissionStreamAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(RetransmissionStreamAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(!RetransmissionStreamAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[test]
    fn retransmissions_stream_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor =
            RetransmissionStreamAuditor::create_auditor(&metrics_store, &config_context);
        let test_packet = TestPacket::new_valid_bootp_packet();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![OpCode::BootRequest.into()])
            .set(SECS_POS, &vec![0, 0]);
        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        auditor.audit(
            &source_ip_address,
            &destination_ip_address,
            &mut ReceivedPacket::new(test_packet.get()).into(),
        );
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_SECS_AVG)
        );

        assert_eq!(
            "",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(
                    METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT
                )
        );

        // Audit 4 packets. The first is not a retransmission. The remaining ones
        // have the increasing secs value.
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        for i in 0..4 {
            let test_packet = TestPacket::new_valid_bootp_packet()
                .set(OPCODE_POS, &vec![OpCode::BootRequest.into()])
                .set(SECS_POS, &vec![0, i]);
            auditor.audit(
                &source_ip_address,
                &destination_ip_address,
                &mut ReceivedPacket::new(&test_packet.get()).into(),
            );
        }
        // 60% of packets were retransmissions. The average secs field value was 1.2.
        auditor.collect_metrics();

        assert_eq!(
            60.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_PERCENT)
        );

        assert_eq!(
            1.2,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_RETRANSMIT_SECS_AVG)
        );

        assert_eq!(
            "2d:20:59:2b:0c:16",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(
                    METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT
                )
        );
    }
}
