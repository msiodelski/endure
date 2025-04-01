//! `opcode` is a module implementing auditors maintaining statistics of
//! the `BOOTP` message types.
//!
//! They recognize `BootRequest` and `BootReply` messages and maintain
//! a total number and the percentage of each message type in the received
//! packets.
//!
//! # Metrics
//!
//! Keeping track of the `BootRequest` and `BootReply` message types can
//! be useful to detect situations when a DHCP server is unable to keep up
//! with the traffic. Another extreme case is when the are only `BootRequest`
//! messages and no `BootReply`. It indicates that the server is down
//! or misconfigured. The [`OpCodeTotalAuditor`] tracks the absolute number
//! of messages of a certain type and their percentages in all received packets.
//! The [`OpCodeStreamAuditor`] tracks the percentages of the message types in
//! most recent packets.

use std::net::Ipv4Addr;

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

use super::{
    common::{AuditProfileCheck, DHCPv4PacketAuditor, DHCPv4PacketAuditorWithMetrics},
    util::{PercentSMA, Percentage, TotalCounter},
};

const METRIC_INDEX_BOOT_REQUEST: usize = 0;
const METRIC_INDEX_BOOT_REPLY: usize = 1;
const METRIC_INDEX_INVALID: usize = 2;

/// An auditor maintaining the total statistics of the `BOOTP` message
/// types.
///
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
#[derive(AuditProfileCheck, Clone, CreateAuditor, Debug, DHCPv4PacketAuditorWithMetrics)]
#[profiles(
    AuditProfile::LiveStreamFull,
    AuditProfile::PcapStreamFull,
    AuditProfile::PcapFinalFull
)]
pub struct OpCodeTotalAuditor {
    metrics_store: SharedMetricsStore,
    message_count: TotalCounter<3>,
}

impl OpCodeTotalAuditor {
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
            message_count: TotalCounter::new(),
        }
    }
}

impl DHCPv4PacketAuditor for OpCodeTotalAuditor {
    fn audit(
        &mut self,
        _source_ip_address: &Ipv4Addr,
        _dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        match packet.write().unwrap().opcode() {
            Ok(opcode) => match opcode {
                OpCode::BootRequest => {
                    self.message_count.increase(METRIC_INDEX_BOOT_REQUEST);
                }
                OpCode::BootReply => {
                    self.message_count.increase(METRIC_INDEX_BOOT_REPLY);
                }
                OpCode::Invalid(_) => {
                    self.message_count.increase(METRIC_INDEX_INVALID);
                }
            },
            Err(_) => {}
        };
    }
}

impl InitMetrics for OpCodeTotalAuditor {
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_BOOT_REQUESTS_COUNT,
            "Total number of the BootRequest messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_BOOT_REPLIES_COUNT,
            "Total number of the BootReply messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_INVALID_COUNT,
            "Total number of the invalid messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT,
            &format_help!(
                "Percentage of the BootRequest messages.",
                MetricScope::Total
            ),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT,
            &format_help!("Percentage of the BootReply messages.", MetricScope::Total),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_INVALID_PERCENT,
            &format_help!("Percentage of the invalid messages.", MetricScope::Total),
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

impl CollectMetrics for OpCodeTotalAuditor {
    fn collect_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_BOOT_REQUESTS_COUNT,
            MetricValue::Int64Value(self.message_count.counter(METRIC_INDEX_BOOT_REQUEST)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_BOOT_REPLIES_COUNT,
            MetricValue::Int64Value(self.message_count.counter(METRIC_INDEX_BOOT_REPLY)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_INVALID_COUNT,
            MetricValue::Int64Value(self.message_count.counter(METRIC_INDEX_INVALID)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT,
            MetricValue::Float64Value(self.message_count.percentage(METRIC_INDEX_BOOT_REQUEST)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT,
            MetricValue::Float64Value(self.message_count.percentage(METRIC_INDEX_BOOT_REPLY)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_INVALID_PERCENT,
            MetricValue::Float64Value(self.message_count.percentage(METRIC_INDEX_INVALID)),
        );
    }
}
/// An auditor maintaining the statistics of the `BOOTP` message types.
///
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
#[derive(AuditProfileCheck, Clone, CreateAuditor, Debug, DHCPv4PacketAuditorWithMetrics)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct OpCodeStreamAuditor {
    metric_scope: MetricScope,
    metrics_store: SharedMetricsStore,
    opcodes: PercentSMA<3>,
}

impl OpCodeStreamAuditor {
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
            opcodes: PercentSMA::new(sampling_window_size),
        }
    }
}

impl DHCPv4PacketAuditor for OpCodeStreamAuditor {
    fn audit(
        &mut self,
        _source_ip_address: &Ipv4Addr,
        _dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    ) {
        match packet.write().unwrap().opcode() {
            Ok(opcode) => match opcode {
                OpCode::BootRequest => {
                    self.opcodes.increase(METRIC_INDEX_BOOT_REQUEST);
                }
                OpCode::BootReply => {
                    self.opcodes.increase(METRIC_INDEX_BOOT_REPLY);
                }
                OpCode::Invalid(_) => {
                    self.opcodes.increase(METRIC_INDEX_INVALID);
                }
            },
            Err(_) => {}
        };
    }
}

impl InitMetrics for OpCodeStreamAuditor {
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT,
            &format_help!("Percentage of the BootRequest messages.", self.metric_scope),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT,
            &format_help!("Percentage of the BootReply messages.", self.metric_scope),
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_BOOTP_OPCODE_INVALID_PERCENT,
            &format_help!("Percentage of the invalid messages.", self.metric_scope),
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

impl CollectMetrics for OpCodeStreamAuditor {
    fn collect_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(METRIC_INDEX_BOOT_REQUEST)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(METRIC_INDEX_BOOT_REPLY)),
        );

        metrics_store.set_metric_value(
            METRIC_BOOTP_OPCODE_INVALID_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(METRIC_INDEX_INVALID)),
        );
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
            opcode::{OpCodeStreamAuditor, OpCodeTotalAuditor},
        },
        proto::{
            bootp::{OpCode, OPCODE_POS},
            dhcp::v4::ReceivedPacket,
            tests::common::TestPacket,
        },
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
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor = OpCodeTotalAuditor::create_auditor(&metrics_store, &config_context);
        let test_packet = TestPacket::new_valid_bootp_packet();
        let test_packet = test_packet.set(OPCODE_POS, &vec![OpCode::BootRequest.into()]);
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        // Audit 5 request packets.
        for _ in 0..5 {
            auditor.audit(&source_ip_address, &destination_ip_address, packet);
        }
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_COUNT)
        );

        assert_eq!(
            0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_COUNT)
        );

        assert_eq!(
            0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_INVALID_COUNT)
        );

        assert_eq!(
            100.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_INVALID_PERCENT)
        );

        // Audit 3 reply packets. Now we have 8 packets audited (5 are requests and
        // 3 are replies).
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        let test_packet = test_packet.set(OPCODE_POS, &vec![OpCode::Invalid(2).into()]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        for _ in 0..3 {
            auditor.audit(&source_ip_address, &destination_ip_address, packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_COUNT)
        );

        assert_eq!(
            3,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_COUNT)
        );

        assert_eq!(
            0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_INVALID_COUNT)
        );

        assert_eq!(
            62.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            37.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_INVALID_PERCENT)
        );

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (5 requests, 3 replies and 2 invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![OpCode::Invalid(3).into()]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        for _ in 0..2 {
            auditor.audit(&source_ip_address, &destination_ip_address, packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_COUNT)
        );

        assert_eq!(
            3,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_COUNT)
        );

        assert_eq!(
            2,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<i64>(METRIC_BOOTP_OPCODE_INVALID_COUNT)
        );

        assert_eq!(
            50.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            30.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            20.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_INVALID_PERCENT)
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
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor = OpCodeStreamAuditor::create_auditor(&metrics_store, &config_context);
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        let test_packet = TestPacket::new_valid_bootp_packet();
        let test_packet = test_packet.set(OPCODE_POS, &vec![OpCode::BootRequest.into()]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        // Audit 5 request packets. They should constitute 100% of all packets.
        for _ in 0..5 {
            auditor.audit(&source_ip_address, &destination_ip_address, packet);
        }
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.clone();

        assert_eq!(
            100.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_INVALID_PERCENT)
        );

        // Audit 3 reply packets. Now we have 8 packets audited (62.5% are requests and 37.5%
        // are replies).
        let source_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        let destination_ip_address = Ipv4Addr::new(192, 168, 1, 2);
        let test_packet = test_packet.set(OPCODE_POS, &vec![OpCode::BootReply.into()]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        for _ in 0..3 {
            auditor.audit(&source_ip_address, &destination_ip_address, packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            62.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            37.5,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            0.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_INVALID_PERCENT)
        );

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (50% of requests, 30% of replies and 20% invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![OpCode::Invalid(3).into()]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_shared_parsable();
        for _ in 0..2 {
            auditor.audit(&source_ip_address, &destination_ip_address, packet);
        }
        auditor.collect_metrics();

        assert_eq!(
            50.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT)
        );

        assert_eq!(
            30.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT)
        );

        assert_eq!(
            20.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_BOOTP_OPCODE_INVALID_PERCENT)
        );
    }
}
