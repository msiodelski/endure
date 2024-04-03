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
    util::{PercentSMA, TotalCounter},
};

/// An auditor maintaining the total statistics of the `BOOTP` message
/// types.
///
/// It recognizes `BootRequest` and `BootReply` messages and maintains
/// a total number and the percentage of each message type in the received
/// packets.
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
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
///
#[derive(AuditProfileCheck, Clone, Debug, FromMetricsStore)]
#[profiles(
    AuditProfile::LiveStreamFull,
    AuditProfile::PcapStreamFull,
    AuditProfile::PcapFinalFull
)]
pub struct OpCodeTotalAuditor {
    metrics_store: SharedMetricsStore,
    message_count: TotalCounter<3>,
}

impl Default for OpCodeTotalAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            message_count: TotalCounter::new(),
        }
    }
}

impl DHCPv4PacketAuditor for OpCodeTotalAuditor {
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>) {
        match packet.opcode() {
            Ok(opcode) => match opcode {
                OpCode::BootRequest => {
                    self.message_count.increase(0);
                }
                OpCode::BootReply => {
                    self.message_count.increase(1);
                }
                OpCode::Invalid(_) => {
                    self.message_count.increase(2);
                }
            },
            Err(_) => {}
        };
    }

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_COUNT,
            MetricValue::Int64Value(self.message_count.counter(0)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_COUNT,
            MetricValue::Int64Value(self.message_count.counter(1)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_COUNT,
            MetricValue::Int64Value(self.message_count.counter(2)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT,
            MetricValue::Float64Value(self.message_count.percentage(0)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT,
            MetricValue::Float64Value(self.message_count.percentage(1)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_PERCENT,
            MetricValue::Float64Value(self.message_count.percentage(2)),
        );
    }
}

impl InitMetrics for OpCodeTotalAuditor {
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
            "Percentage of the BootRequest messages in all messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT,
            "Percentage of the BootReply messages in all messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_INVALID_PERCENT,
            "Percentage of the invalid messages in all messages.",
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

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
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
///
#[derive(AuditProfileCheck, Clone, Debug, FromMetricsStore)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct OpCodeStreamAuditor {
    metrics_store: SharedMetricsStore,
    opcodes: PercentSMA<3, 100>,
}

impl Default for OpCodeStreamAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            opcodes: PercentSMA::new(),
        }
    }
}

impl DHCPv4PacketAuditor for OpCodeStreamAuditor {
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>) {
        match packet.opcode() {
            Ok(opcode) => match opcode {
                OpCode::BootRequest => {
                    self.opcodes.increase(0usize);
                }
                OpCode::BootReply => {
                    self.opcodes.increase(1usize);
                }
                OpCode::Invalid(_) => {
                    self.opcodes.increase(2usize);
                }
            },
            Err(_) => {}
        };
    }

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100,
            MetricValue::Float64Value(self.opcodes.average(0)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT_100,
            MetricValue::Float64Value(self.opcodes.average(1)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_PERCENT_100,
            MetricValue::Float64Value(self.opcodes.average(2)),
        );
    }
}

impl InitMetrics for OpCodeStreamAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100,
            "Percentage of the BootRequest messages in last 100 messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT_100,
            "Percentage of the BootReply messages in last 100 messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_INVALID_PERCENT_100,
            "Percentage of the invalid messages in last 100 messages.",
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
            opcode::{OpCodeStreamAuditor, OpCodeTotalAuditor},
        },
        proto::{bootp::OPCODE_POS, dhcp::v4::ReceivedPacket, tests::common::TestBootpPacket},
    };

    #[test]
    fn opcode_total_auditor_profiles() {
        assert!(OpCodeTotalAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(OpCodeTotalAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(OpCodeTotalAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[test]
    fn opcode_total_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = OpCodeTotalAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet.set(OPCODE_POS, &vec![1]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        // Audit 5 request packets.
        for _ in 0..5 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_BOOT_REQUESTS_COUNT)
        );

        assert_eq!(
            0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_BOOT_REPLIES_COUNT)
        );

        assert_eq!(
            0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_INVALID_COUNT)
        );

        assert_eq!(
            100.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_INVALID_PERCENT)
        );

        // Audit 3 reply packets. Now we have 8 packets audited (5 are requests and
        // 3 are replies).
        let test_packet = test_packet.set(OPCODE_POS, &vec![2]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..3 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_BOOT_REQUESTS_COUNT)
        );

        assert_eq!(
            3,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_BOOT_REPLIES_COUNT)
        );

        assert_eq!(
            0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_INVALID_COUNT)
        );

        assert_eq!(
            62.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            37.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_INVALID_PERCENT)
        );

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (5 requests, 3 replies and 2 invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![3]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..2 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_BOOT_REQUESTS_COUNT)
        );

        assert_eq!(
            3,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_BOOT_REPLIES_COUNT)
        );

        assert_eq!(
            2,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_OPCODE_INVALID_COUNT)
        );

        assert_eq!(
            50.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            30.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            20.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_INVALID_PERCENT)
        );
    }

    #[test]
    fn opcode_stream_auditor_profiles() {
        assert!(OpCodeStreamAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(OpCodeStreamAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(!OpCodeStreamAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[test]
    fn opcode_stream_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = OpCodeStreamAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet.set(OPCODE_POS, &vec![1]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        // Audit 5 request packets. They should constitute 100% of all packets.
        for _ in 0..5 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            100.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REPLIES_PERCENT_100)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_INVALID_PERCENT_100)
        );

        // Audit 3 reply packets. Now we have 8 packets audited (62.5% are requests and 37.5%
        // are replies).
        let test_packet = test_packet.set(OPCODE_POS, &vec![2]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..3 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            62.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100)
        );

        assert_eq!(
            37.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REPLIES_PERCENT_100)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_INVALID_PERCENT_100)
        );

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (50% of requests, 30% of replies and 20% invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![3]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..2 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            50.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100)
        );

        assert_eq!(
            30.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_BOOT_REPLIES_PERCENT_100)
        );

        assert_eq!(
            20.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_OPCODE_INVALID_PERCENT_100)
        );
    }
}
