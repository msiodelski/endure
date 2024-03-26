//! `retransmission` is a module implementing the auditors analyzing the
//! packet retransmissions looking into the `secs` values.

use super::{
    common::{AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor},
    util::{MovingRanks, RoundedSMA},
};
use crate::auditor::metric::*;
use crate::proto::{bootp::OpCode, dhcp::v4};
use endure_lib::metric::{FromMetricsStore, InitMetrics, Metric, MetricValue, SharedMetricsStore};
use endure_macros::{AuditProfileCheck, FromMetricsStore};

/// An auditor maintaining the statistics of DHCP retransmissions.
///
/// The auditor looks into the `secs` field of the `BOOTP` messages. If this
/// field has a value greater than zero it indicates that the client has been
/// unable to allocate a lease in the previous attempts and retransmits.
///
/// # Metrics
///
/// Client retransmissions often occur when the server is unable to keep up
/// with the DHCP traffic load. A high average value of the `secs` field and
/// a high average number of retransmissions indicate that the server has
/// hard time to keep up with the traffic.
///
/// The auditor also keeps track of the MAC address of the client who has been
/// trying to get a lease for a longest period of time in last 1000 packets.
///
#[derive(AuditProfileCheck, Debug, FromMetricsStore)]
#[profiles(AuditProfile::LiveStreamAll, AuditProfile::PcapAll)]
pub struct RetransmissionAuditor {
    metrics_store: SharedMetricsStore,
    retransmits: RoundedSMA<10, 100>,
    secs: RoundedSMA<10, 100>,
    longest_trying_client: MovingRanks<String, u16, 1, 100>,
}

impl Default for RetransmissionAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            retransmits: RoundedSMA::new(),
            secs: RoundedSMA::new(),
            longest_trying_client: MovingRanks::new(),
        }
    }
}

impl DHCPv4PacketAuditor for RetransmissionAuditor {
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>) {
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
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_PERCENT,
            "Percentage of the retransmissions in the mssages sent by clients.",
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_SECS_AVG,
            "Average retransmission time (i.e. average time in retransmissions to acquire a new lease).",
            MetricValue::Float64Value(self.secs.average()),
        ));
        if let Some(longest_trying_client) = self.longest_trying_client.get_rank(0) {
            metrics_store.set_metric(Metric::new(
                METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
                "MAC address of the the client who has been trying the longest to acquire a lease.",
                MetricValue::StringValue(longest_trying_client.id.clone()),
            ));
        }
    }
}

impl InitMetrics for RetransmissionAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_PERCENT,
            "Percentage of the retransmissions in the mssages sent by clients.",
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_SECS_AVG,
            "Average retransmission time (i.e. average time in retransmissions to acquire a new lease).",
            MetricValue::Float64Value(self.secs.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
            "MAC address of the the client who has been trying the longest to acquire a lease.",
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
            retransmission::RetransmissionAuditor,
        },
        proto::{
            bootp::{OPCODE_POS, SECS_POS},
            dhcp::v4::ReceivedPacket,
            tests::common::TestBootpPacket,
        },
    };

    #[test]
    fn retransmissions_auditor_profiles() {
        assert!(RetransmissionAuditor::has_audit_profile(
            &AuditProfile::LiveStreamAll
        ));
        assert!(RetransmissionAuditor::has_audit_profile(
            &AuditProfile::PcapAll
        ));
    }

    #[test]
    fn retransmissions_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = RetransmissionAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![1])
            .set(SECS_POS, &vec![0, 0]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();

        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        auditor.audit(packet);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        let retransmit_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_PERCENT);
        assert!(retransmit_percent.is_some());
        assert_eq!(
            0.0,
            retransmit_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_secs_avg = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_SECS_AVG);
        assert!(retransmit_secs_avg.is_some());
        assert_eq!(
            0.0,
            retransmit_secs_avg.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_longest_trying_client = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT);
        assert!(retransmit_longest_trying_client.is_some());
        assert_eq!(
            "",
            retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
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

        let retransmit_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_PERCENT);
        assert!(retransmit_percent.is_some());
        assert_eq!(
            60.0,
            retransmit_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_secs_avg = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_SECS_AVG);
        assert!(retransmit_secs_avg.is_some());
        assert_eq!(
            1.2,
            retransmit_secs_avg.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_longest_trying_client = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT);
        assert!(retransmit_longest_trying_client.is_some());
        assert_eq!(
            "2d:20:59:2b:0c:16",
            retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
        );
    }
}
