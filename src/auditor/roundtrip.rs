//! `roundtrip` is a module implementing auditors maintaining statistics of
//! how long it takes to complete a DHCP transaction.
//!
//! The auditors measure the timestamps between capturing a client request and
//! and server response to this request.

use super::{
    common::{
        AuditProfileCheck, DHCPv4Transaction, DHCPv4TransactionAuditor, DHCPv4TransactionKind,
    },
    metric::{
        METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG,
        METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG_100,
        METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG,
        METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG_100,
        METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG,
        METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG_100,
    },
    util::{RoundedSMA, RoundedSTA},
};
use crate::auditor::common::AuditProfile;
use endure_lib::metric::{FromMetricsStore, InitMetrics, Metric, MetricValue, SharedMetricsStore};
use endure_macros::{AuditProfileCheck, FromMetricsStore};

/// An auditor maintaining the average time between different exchanges
/// in the DORA exchange in all messages.
///
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
///
#[derive(AuditProfileCheck, Debug, FromMetricsStore)]
#[profiles(AuditProfile::PcapFinalFull)]
pub struct DORARoundtripTotalAuditor {
    do_roundtrip: RoundedSTA<1>,
    ra_roundtrip: RoundedSTA<1>,
    dora_roundtrip: RoundedSTA<1>,
    metrics_store: SharedMetricsStore,
}

impl Default for DORARoundtripTotalAuditor {
    fn default() -> Self {
        Self {
            dora_roundtrip: RoundedSTA::new(),
            do_roundtrip: RoundedSTA::new(),
            ra_roundtrip: RoundedSTA::new(),
            metrics_store: Default::default(),
        }
    }
}

impl DHCPv4TransactionAuditor for DORARoundtripTotalAuditor {
    fn audit(&mut self, transaction: &mut DHCPv4Transaction) {
        // Need to own the transaction because we're going to access
        // it several times.
        let transaction = transaction.to_owned();
        let kind = transaction.kind();
        if kind.eq(&DHCPv4TransactionKind::FourWayExchange(true))
            || kind.eq(&DHCPv4TransactionKind::Discovery(true))
        {
            // DO exchange.
            let discover = transaction.discover.unwrap();
            let offer = transaction.offer.as_ref().unwrap();
            if let Ok(duration) = offer.timestamp().duration_since(discover.timestamp()) {
                self.do_roundtrip
                    .add_sample((duration.as_micros() as u64) / 100);
            }
            if kind.eq(&DHCPv4TransactionKind::FourWayExchange(true)) {
                // DORA exchange.
                let ack = transaction.ack.unwrap();
                if let Ok(duration) = ack.timestamp().duration_since(discover.timestamp()) {
                    self.dora_roundtrip
                        .add_sample((duration.as_micros() as u64) / 100);
                }
                // RA exchange.
                let request = transaction.request.unwrap();
                if let Ok(duration) = ack.timestamp().duration_since(request.timestamp()) {
                    self.ra_roundtrip
                        .add_sample((duration.as_micros() as u64) / 100);
                }
            }
        }
    }

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG,
            MetricValue::Float64Value(self.dora_roundtrip.average() / 10f64),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG,
            MetricValue::Float64Value(self.do_roundtrip.average() / 10f64),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG,
            MetricValue::Float64Value(self.ra_roundtrip.average() / 10f64),
        );
    }
}

impl InitMetrics for DORARoundtripTotalAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG,
            "Average time in milliseconds to perform a 4-way (DORA) exchange in all transactions.",
            MetricValue::Float64Value(self.dora_roundtrip.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG,
            "Average time in milliseconds to complete a successful Discover/Offer exchange in all transactions.",
            MetricValue::Float64Value(self.do_roundtrip.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG,
            "Average time in milliseconds to complete a successful Request/Ack exchange within a 4-way (DORA) exchange in all transactions.",
            MetricValue::Float64Value(self.ra_roundtrip.average()),
        ));
    }
}

/// An auditor maintaining the average time between different exchanges
/// in the DORA exchange.
///
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
///
#[derive(AuditProfileCheck, Debug, FromMetricsStore)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct DORARoundtripStreamAuditor {
    do_roundtrip: RoundedSMA<1, 100>,
    ra_roundtrip: RoundedSMA<1, 100>,
    dora_roundtrip: RoundedSMA<1, 100>,
    metrics_store: SharedMetricsStore,
}

impl Default for DORARoundtripStreamAuditor {
    fn default() -> Self {
        Self {
            dora_roundtrip: RoundedSMA::new(),
            do_roundtrip: RoundedSMA::new(),
            ra_roundtrip: RoundedSMA::new(),
            metrics_store: Default::default(),
        }
    }
}

impl DHCPv4TransactionAuditor for DORARoundtripStreamAuditor {
    fn audit(&mut self, transaction: &mut DHCPv4Transaction) {
        // Need to own the transaction because we're going to access
        // it several times.
        let transaction = transaction.to_owned();
        let kind = transaction.kind();
        if kind.eq(&DHCPv4TransactionKind::FourWayExchange(true))
            || kind.eq(&DHCPv4TransactionKind::Discovery(true))
        {
            // DO exchange.
            let discover = transaction.discover.unwrap();
            let offer = transaction.offer.as_ref().unwrap();
            if let Ok(duration) = offer.timestamp().duration_since(discover.timestamp()) {
                self.do_roundtrip
                    .add_sample((duration.as_micros() as u64) / 100);
            }
            if kind.eq(&DHCPv4TransactionKind::FourWayExchange(true)) {
                // DORA exchange.
                let ack = transaction.ack.unwrap();
                if let Ok(duration) = ack.timestamp().duration_since(discover.timestamp()) {
                    self.dora_roundtrip
                        .add_sample((duration.as_micros() as u64) / 100);
                }
                // RA exchange.
                let request = transaction.request.unwrap();
                if let Ok(duration) = ack.timestamp().duration_since(request.timestamp()) {
                    self.ra_roundtrip
                        .add_sample((duration.as_micros() as u64) / 100);
                }
            }
        }
    }

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG_100,
            MetricValue::Float64Value(self.dora_roundtrip.average() / 10f64),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG_100,
            MetricValue::Float64Value(self.do_roundtrip.average() / 10f64),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG_100,
            MetricValue::Float64Value(self.ra_roundtrip.average() / 10f64),
        );
    }
}

impl InitMetrics for DORARoundtripStreamAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG_100,
            "Average time in milliseconds to perform a 4-way (DORA) exchange in last 100 transactions.",
            MetricValue::Float64Value(self.dora_roundtrip.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG_100,
            "Average time in milliseconds to complete a successful Discover/Offer exchange in last 100 transactions.",
            MetricValue::Float64Value(self.do_roundtrip.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG_100,
            "Average time in milliseconds to complete a successful Request/Ack exchange within a 4-way (DORA) exchange in last 100 transactions.",
            MetricValue::Float64Value(self.ra_roundtrip.average()),
        ));
    }
}

#[cfg(test)]
mod tests {
    use endure_lib::{
        metric::{FromMetricsStore, MetricsStore},
        time_wrapper::TimeWrapper,
    };

    use crate::{
        auditor::{
            common::{
                AuditProfile, AuditProfileCheck, DHCPv4Transaction, DHCPv4TransactionAuditor,
            },
            metric::{
                METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG,
                METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG_100,
                METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG,
                METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG_100,
                METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG,
                METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG_100,
            },
            roundtrip::{DORARoundtripStreamAuditor, DORARoundtripTotalAuditor},
        },
        proto::{
            dhcp::v4::{MessageType, ReceivedPacket},
            tests::common::TestPacket,
        },
    };

    fn create_transaction(tv_sec: libc::time_t, tv_usec: libc::suseconds_t) -> DHCPv4Transaction {
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Discover).get(),
        )
        .into_shared_parsable();

        let wrapped_packet = TimeWrapper::from_timeval(libc::timeval { tv_sec, tv_usec }, packet);
        let result = DHCPv4Transaction::from_wrapped_packet(wrapped_packet);
        assert!(result.is_ok());
        result.unwrap()
    }

    fn insert_packet_into_transaction(
        tv_sec: libc::time_t,
        tv_usec: libc::suseconds_t,
        message_type: MessageType,
        transaction: &mut DHCPv4Transaction,
    ) {
        let packet =
            ReceivedPacket::new(TestPacket::new_dhcp_packet_with_message_type(message_type).get())
                .into_shared_parsable();
        let packet = TimeWrapper::from_timeval(libc::timeval { tv_sec, tv_usec }, packet);
        let result = transaction.insert(packet);
        assert!(result.is_ok());
    }

    #[test]
    fn roundtrip_total_auditor_profiles() {
        assert!(!DORARoundtripTotalAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(!DORARoundtripTotalAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
        assert!(DORARoundtripTotalAuditor::has_audit_profile(
            &AuditProfile::PcapFinalFull
        ));
    }

    #[test]
    fn roundtrip_total_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = DORARoundtripTotalAuditor::from_metrics_store(&metrics_store);

        // Create a transaction holding DHCPDISCOVER.
        let mut transaction = create_transaction(5, 100000);

        auditor.audit(&mut transaction);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        for metric in vec![
            METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG,
            METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG,
            METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG,
        ] {
            assert_eq!(
                0.0,
                metrics_store_ref
                    .read()
                    .unwrap()
                    .get_metric_value_unwrapped::<f64>(metric)
            );
        }

        // Complete the transaction by adding the rest of the packets of the
        // 4-way exchange.
        insert_packet_into_transaction(5, 300000, MessageType::Offer, &mut transaction);
        insert_packet_into_transaction(6, 578000, MessageType::Request, &mut transaction);
        insert_packet_into_transaction(8, 200000, MessageType::Ack, &mut transaction);

        auditor.audit(&mut transaction);
        auditor.collect_metrics();

        assert_eq!(
            3100.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG)
        );

        assert_eq!(
            200.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(
                    METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG
                )
        );

        assert_eq!(
            1622.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(
                    METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG
                )
        );
    }

    #[test]
    fn roundtrip_stream_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = DORARoundtripStreamAuditor::from_metrics_store(&metrics_store);

        // Create a transaction holding DHCPDISCOVER.
        let mut transaction = create_transaction(5, 100000);

        auditor.audit(&mut transaction);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        for metric in vec![
            METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG_100,
            METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG_100,
            METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG_100,
        ] {
            assert_eq!(
                0.0,
                metrics_store_ref
                    .read()
                    .unwrap()
                    .get_metric_value_unwrapped::<f64>(metric)
            );
        }

        // Complete the transaction by adding the rest of the packets of the
        // 4-way exchange.
        insert_packet_into_transaction(5, 500000, MessageType::Offer, &mut transaction);
        insert_packet_into_transaction(6, 578000, MessageType::Request, &mut transaction);
        insert_packet_into_transaction(8, 200000, MessageType::Ack, &mut transaction);

        auditor.audit(&mut transaction);
        auditor.collect_metrics();

        assert_eq!(
            3100.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(
                    METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG_100
                )
        );

        assert_eq!(
            400.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(
                    METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG_100
                )
        );

        assert_eq!(
            1622.0,
            metrics_store_ref
                .read()
                .unwrap()
                .get_metric_value_unwrapped::<f64>(
                    METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG_100
                )
        );
    }
}
