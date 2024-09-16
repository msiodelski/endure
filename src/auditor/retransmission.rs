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
    common::{AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor},
    util::{MovingRanks, RoundedSMA, RoundedSTA},
};
use crate::auditor::metric::*;
use crate::proto::{bootp::OpCode, dhcp::v4};
use endure_lib::metric::{FromMetricsStore, InitMetrics, Metric, MetricValue, SharedMetricsStore};
use endure_macros::{AuditProfileCheck, FromMetricsStore};

/// An auditor maintaining the statistics of DHCP retransmissions in all messages.
///
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
///
#[derive(AuditProfileCheck, Debug, FromMetricsStore)]
#[profiles(AuditProfile::PcapFinalFull)]
pub struct RetransmissionTotalAuditor {
    metrics_store: SharedMetricsStore,
    retransmits: RoundedSTA<10>,
    secs: RoundedSTA<10>,
    longest_trying_client: MovingRanks<String, u16, 1, { usize::MAX }>,
}

impl Default for RetransmissionTotalAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            retransmits: RoundedSTA::new(),
            secs: RoundedSTA::new(),
            longest_trying_client: MovingRanks::new(),
        }
    }
}

impl DHCPv4PacketAuditor for RetransmissionTotalAuditor {
    fn audit(&mut self, packet: &mut v4::PartiallyParsedPacket) {
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

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_RETRANSMIT_PERCENT,
            MetricValue::Float64Value(self.retransmits.average()),
        );

        metrics_store.set_metric_value(
            METRIC_RETRANSMIT_SECS_AVG,
            MetricValue::Float64Value(self.secs.average()),
        );

        if let Some(longest_trying_client) = self.longest_trying_client.get_rank(0) {
            metrics_store.set_metric_value(
                METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
                MetricValue::StringValue(longest_trying_client.id.clone()),
            );
        }
    }
}

impl InitMetrics for RetransmissionTotalAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_PERCENT,
            "Percentage of the retransmissions in all messages sent by clients.",
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_SECS_AVG,
            "Average retransmission time in all messages (i.e. average time in retransmissions to acquire a new lease).",
            MetricValue::Float64Value(self.secs.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
            "MAC address of the the client who has been trying the longest to acquire a lease in all messages.",
            MetricValue::StringValue("".to_string()),
        ));
    }
}

/// An auditor maintaining the statistics of DHCP retransmissions.
///
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
///
#[derive(AuditProfileCheck, Debug, FromMetricsStore)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct RetransmissionStreamAuditor {
    metrics_store: SharedMetricsStore,
    retransmits: RoundedSMA<10, 100>,
    secs: RoundedSMA<10, 100>,
    longest_trying_client: MovingRanks<String, u16, 1, 100>,
}

impl Default for RetransmissionStreamAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            retransmits: RoundedSMA::new(),
            secs: RoundedSMA::new(),
            longest_trying_client: MovingRanks::new(),
        }
    }
}

impl DHCPv4PacketAuditor for RetransmissionStreamAuditor {
    fn audit(&mut self, packet: &mut v4::PartiallyParsedPacket) {
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

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_RETRANSMIT_PERCENT_100,
            MetricValue::Float64Value(self.retransmits.average()),
        );

        metrics_store.set_metric_value(
            METRIC_RETRANSMIT_SECS_AVG_100,
            MetricValue::Float64Value(self.secs.average()),
        );

        if let Some(longest_trying_client) = self.longest_trying_client.get_rank(0) {
            metrics_store.set_metric_value(
                METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT_100,
                MetricValue::StringValue(longest_trying_client.id.clone()),
            );
        }
    }
}

impl InitMetrics for RetransmissionStreamAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_PERCENT_100,
            "Percentage of the retransmissions in the last 100 messages sent by clients.",
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_SECS_AVG_100,
            "Average retransmission time in the last 100 messages (i.e. average time in retransmissions to acquire a new lease).",
            MetricValue::Float64Value(self.secs.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT_100,
            "MAC address of the the client who has been trying the longest to acquire a lease in the last 100 messages.",
            MetricValue::StringValue("".to_string()),
        ));
    }
}

#[cfg(test)]
mod tests {
    use endure_lib::metric::{FromMetricsStore, MetricsStore};

    use crate::{
        auditor::{
            common::{AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor},
            metric::*,
            retransmission::{RetransmissionStreamAuditor, RetransmissionTotalAuditor},
        },
        proto::{
            bootp::{OPCODE_POS, SECS_POS},
            dhcp::v4::ReceivedPacket,
            tests::common::TestBootpPacket,
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
        let mut auditor = RetransmissionTotalAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![1])
            .set(SECS_POS, &vec![0, 0]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();

        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        auditor.audit(packet);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_SECS_AVG)
        );

        assert_eq!(
            "",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT)
        );

        // Audit 4 packets. The first is not a retransmission. The remaining ones
        // have the increasing secs value.
        for i in 0..4 {
            let test_packet = TestBootpPacket::new()
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = &mut ReceivedPacket::new(&test_packet.get()).into_parsable();
            auditor.audit(packet);
        }
        // 60% of packets were retransmissions. The average secs field value was 1.2.
        auditor.collect_metrics();

        assert_eq!(
            60.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_PERCENT)
        );

        assert_eq!(
            1.2,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_SECS_AVG)
        );

        assert_eq!(
            "2d:20:59:2b:0c:16",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT)
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
        let mut auditor = RetransmissionStreamAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![1])
            .set(SECS_POS, &vec![0, 0]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();

        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        auditor.audit(packet);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_PERCENT_100)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_SECS_AVG_100)
        );

        assert_eq!(
            "",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT_100)
        );

        // Audit 4 packets. The first is not a retransmission. The remaining ones
        // have the increasing secs value.
        for i in 0..4 {
            let test_packet = TestBootpPacket::new()
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = &mut ReceivedPacket::new(&test_packet.get()).into_parsable();
            auditor.audit(packet);
        }
        // 60% of packets were retransmissions. The average secs field value was 1.2.
        auditor.collect_metrics();

        assert_eq!(
            60.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_PERCENT_100)
        );

        assert_eq!(
            1.2,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_RETRANSMIT_SECS_AVG_100)
        );

        assert_eq!(
            "2d:20:59:2b:0c:16",
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<String>(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT_100)
        );
    }
}
