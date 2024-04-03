//! `opcode` is a module implementing the auditors analyzing the
//! `OpCode` values in the `BOOTP` packets.

use crate::{
    auditor::{common::AuditProfile, metric::*},
    proto::{bootp::OpCode, dhcp::v4},
};
use endure_lib::metric::{FromMetricsStore, InitMetrics, Metric, MetricValue, SharedMetricsStore};
use endure_macros::{AuditProfileCheck, FromMetricsStore};

use super::{
    common::{AuditProfileCheck, DHCPv4PacketAuditor},
    util::PercentSMA,
};

/// An auditor maintaining the statistics of the `BOOTP` message types.
///
/// It recognizes `BootRequest` and `BootReply` messages and maintains
/// an average percentage of each message type in the received packets
/// stream.
///
/// # Metrics
///
/// Keeping track of the `BootRequest` and `BootReply` message types can
/// be useful to detect situations when a DHCP server is unable to keep up
/// with the traffic. Another extreme case is when the are only `BootRequest`
/// messages and no `BootReply`. It indicates that the server is down
/// or misconfigured.
///
/// The auditor also returns an average number of invalid messages
/// (i.e., neither `BootRequest` nor `BootReply`).
///
#[derive(AuditProfileCheck, Clone, Debug, FromMetricsStore)]
#[profiles(
    AuditProfile::LiveStreamFull,
    AuditProfile::PcapStreamFull,
    AuditProfile::PcapFinalFull
)]
pub struct OpCodeAuditor {
    metrics_store: SharedMetricsStore,
    requests_count: i64,
    replies_count: i64,
    invalid_count: i64,
    opcodes: PercentSMA<3, 100>,
}

impl Default for OpCodeAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            requests_count: Default::default(),
            replies_count: Default::default(),
            invalid_count: Default::default(),
            opcodes: PercentSMA::new(),
        }
    }
}

impl DHCPv4PacketAuditor for OpCodeAuditor {
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>) {
        match packet.opcode() {
            Ok(opcode) => match opcode {
                OpCode::BootRequest => {
                    self.requests_count += 1;
                    self.opcodes.increase(0usize);
                }
                OpCode::BootReply => {
                    self.replies_count += 1;
                    self.opcodes.increase(1usize);
                }
                OpCode::Invalid(_) => {
                    self.invalid_count += 1;
                    self.opcodes.increase(2usize);
                }
            },
            Err(_) => {}
        };
    }

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_COUNT,
            MetricValue::Int64Value(self.requests_count),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_COUNT,
            MetricValue::Int64Value(self.replies_count),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_COUNT,
            MetricValue::Int64Value(self.invalid_count),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(0)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(1)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(2)),
        );
    }
}

impl InitMetrics for OpCodeAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REQUESTS_COUNT,
            "Total number of the BootRequest messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REPLIES_COUNT,
            "Total number of the BootReply messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_INVALID_COUNT,
            "Total number of the invalid messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT,
            "Percentage of the BootRequest messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT,
            "Percentage of the BootReply messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_INVALID_PERCENT,
            "Percentage of the invalid messages.",
            MetricValue::Float64Value(Default::default()),
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
            opcode::OpCodeAuditor,
        },
        proto::{bootp::OPCODE_POS, dhcp::v4::ReceivedPacket, tests::common::TestBootpPacket},
    };

    #[test]
    fn opcode_auditor_profiles() {
        assert!(OpCodeAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(OpCodeAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
    }

    #[test]
    fn opcode_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = OpCodeAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet.set(OPCODE_POS, &vec![1]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        // Audit 5 request packets. They should constitute 100% of all packets.
        for _ in 0..5 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.clone();

        let opcode_boot_requests_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_COUNT);
        assert!(opcode_boot_requests_count.is_some());
        assert_eq!(
            5,
            opcode_boot_requests_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_boot_replies_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_COUNT);
        assert!(opcode_boot_replies_count.is_some());
        assert_eq!(
            0,
            opcode_boot_replies_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_invalid_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_COUNT);
        assert!(opcode_invalid_count.is_some());
        assert_eq!(
            0,
            opcode_invalid_count.unwrap().get_value_unwrapped::<i64>()
        );

        let opcode_boot_requests_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            100.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_replies_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            0.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        // Audit 3 reply packets. Now we have 8 packets audited (62.5% are requests and 37.5%
        // are replies).
        let test_packet = test_packet.set(OPCODE_POS, &vec![2]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..3 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        let opcode_boot_requests_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_COUNT);
        assert!(opcode_boot_requests_count.is_some());
        assert_eq!(
            5,
            opcode_boot_requests_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_boot_replies_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_COUNT);
        assert!(opcode_boot_replies_count.is_some());
        assert_eq!(
            3,
            opcode_boot_replies_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_invalid_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_COUNT);
        assert!(opcode_invalid_count.is_some());
        assert_eq!(
            0,
            opcode_invalid_count.unwrap().get_value_unwrapped::<i64>()
        );

        let opcode_boot_requests_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            62.5,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_replies_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            37.5,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (50% of requests, 30% of replies and 20% invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![3]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..2 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        let opcode_boot_requests_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_COUNT);
        assert!(opcode_boot_requests_count.is_some());
        assert_eq!(
            5,
            opcode_boot_requests_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_boot_replies_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_COUNT);
        assert!(opcode_boot_replies_count.is_some());
        assert_eq!(
            3,
            opcode_boot_replies_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_invalid_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_COUNT);
        assert!(opcode_invalid_count.is_some());
        assert_eq!(
            2,
            opcode_invalid_count.unwrap().get_value_unwrapped::<i64>()
        );

        let opcode_boot_requests_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            50.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_replies_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            30.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            20.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );
    }
}
