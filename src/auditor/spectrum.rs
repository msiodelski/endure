//! `spectrum` is a module implementing auditors maintaining statistics of
//! the DHCPv4 traffic types distribution.
//!
//! The auditors measure the proportions of the different types of DHCPv4
//! transactions. In particular, it distinguishes between the 4-way exchanges
//! renewals, rebinds, informs and releases. Knowing these proportions can help
//! discovering renewal or rebind storms related to the issues with the DHCPv4 server.
//! It can also help to understand how the lease lifetimes affect the network
//! congestion.

use super::{
    common::{
        AuditProfileCheck, DHCPv4Transaction, DHCPv4TransactionAuditor,
        DHCPv4TransactionAuditorWithMetrics, DHCPv4TransactionKind,
    },
    metric::{
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_COUNT, METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
    },
    util::{FromMetricScope, PercentSMA, Percentage, TotalCounter},
};
use crate::auditor::common::AuditProfile;
use endure_lib::{
    auditor::{CreateAuditor, SharedAuditConfigContext},
    format_help,
    metric::{CollectMetrics, InitMetrics, Metric, MetricScope, MetricValue, SharedMetricsStore},
};
use endure_macros::{AuditProfileCheck, CreateAuditor, DHCPv4TransactionAuditorWithMetrics};
use std::fmt::Debug;

const METRIC_INDEX_ATTEMPTED_DORA: usize = 0;
const METRIC_INDEX_ATTEMPTED_INFORM: usize = 1;
const METRIC_INDEX_ATTEMPTED_RENEW: usize = 2;
const METRIC_INDEX_ATTEMPTED_REBIND: usize = 3;
const METRIC_INDEX_ATTEMPTED_RELEASE: usize = 4;

#[derive(Debug)]
struct DHCPv4SpectrumAuditor<MetricTrackingImpl> {
    metric_scope: MetricScope,
    metrics_store: SharedMetricsStore,
    exchange_count: MetricTrackingImpl,
}

impl<MetricTrackingImpl> DHCPv4SpectrumAuditor<MetricTrackingImpl>
where
    MetricTrackingImpl: FromMetricScope,
{
    pub fn new(metrics_store: &SharedMetricsStore, metric_scope: MetricScope) -> Self {
        Self {
            metrics_store: metrics_store.clone(),
            exchange_count: MetricTrackingImpl::from_metric_scope(&metric_scope),
            metric_scope,
        }
    }
}

impl<MetricTrackingImpl> DHCPv4TransactionAuditor for DHCPv4SpectrumAuditor<MetricTrackingImpl>
where
    MetricTrackingImpl: Percentage + Debug + Send + Sync,
{
    fn audit(&mut self, transaction: &mut DHCPv4Transaction) {
        // Need to own the transaction because we're going to access
        // it several times.
        let transaction = transaction.to_owned();
        let kind = transaction.kind();
        match kind {
            DHCPv4TransactionKind::Discovery(false) => {
                self.exchange_count.increase(METRIC_INDEX_ATTEMPTED_DORA);
            }
            DHCPv4TransactionKind::InfRequest => {
                self.exchange_count.increase(METRIC_INDEX_ATTEMPTED_INFORM);
            }
            DHCPv4TransactionKind::Renewal => {
                match transaction.request.and_then(|request| {
                    // Check if the server identifier is present in the request. It is
                    // included in the renew and absent in the rebind.
                    request
                        .get()
                        .write()
                        .ok()
                        .and_then(|mut packet| packet.option_54_server_identifier().ok())
                        .flatten()
                }) {
                    Some(_) => self.exchange_count.increase(METRIC_INDEX_ATTEMPTED_RENEW),
                    None => self.exchange_count.increase(METRIC_INDEX_ATTEMPTED_REBIND),
                }
            }
            DHCPv4TransactionKind::Release => {
                self.exchange_count.increase(METRIC_INDEX_ATTEMPTED_RELEASE);
            }
            _ => {}
        }
    }
}

impl<MetricTrackingImpl> InitMetrics for DHCPv4SpectrumAuditor<MetricTrackingImpl>
where
    MetricTrackingImpl: Percentage,
{
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
            &format_help!(
                "Percentage of attempted DORA exchanges in all exchanges.",
                self.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
            &format_help!(
                "Percentage of attempted Inform exchanges in all exchanges.",
                self.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
            &format_help!(
                "Percentage of attempted Renew exchanges in all exchanges.",
                self.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
            &format_help!(
                "Percentage of attempted Rebind exchanges in all exchanges.",
                self.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
            &format_help!(
                "Percentage of attempted Release messages in all exchanges.",
                self.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

impl<MetricTrackingImpl> CollectMetrics for DHCPv4SpectrumAuditor<MetricTrackingImpl>
where
    MetricTrackingImpl: Percentage,
{
    fn collect_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
            MetricValue::Float64Value(self.exchange_count.percentage(METRIC_INDEX_ATTEMPTED_DORA)),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
            MetricValue::Float64Value(
                self.exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_INFORM),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
            MetricValue::Float64Value(self.exchange_count.percentage(METRIC_INDEX_ATTEMPTED_RENEW)),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
            MetricValue::Float64Value(
                self.exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_REBIND),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
            MetricValue::Float64Value(
                self.exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_RELEASE),
            ),
        );
    }
}

/// An auditor counting different kinds of DHCPv4 transactions.
///
/// # Transaction Types
///
/// The auditor distinguishes between the following transaction types:
///
/// - `DORA`: Discover, Offer, Request, Ack
/// - `Inform`: Inform, Ack
/// - `Renew`: Renew, Ack
/// - `Rebind`: Renew (without server identifier), Ack
/// - `Release`: Release
///
/// # Profiles
///
/// This auditor is used for analyzing capture files when the metrics are displayed
/// at the end of the analysis.
///
#[derive(AuditProfileCheck, CreateAuditor, Debug, DHCPv4TransactionAuditorWithMetrics)]
#[profiles(AuditProfile::PcapFinalFull)]
pub struct DHCPv4SpectrumTotalAuditor {
    auditor: DHCPv4SpectrumAuditor<TotalCounter<5>>,
}

impl DHCPv4SpectrumTotalAuditor {
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
            auditor: DHCPv4SpectrumAuditor::new(metrics_store, MetricScope::Total),
        }
    }
}

impl DHCPv4TransactionAuditor for DHCPv4SpectrumTotalAuditor {
    fn audit(&mut self, transaction: &mut DHCPv4Transaction) {
        self.auditor.audit(transaction)
    }
}

impl InitMetrics for DHCPv4SpectrumTotalAuditor {
    fn init_metrics(&self) {
        let mut metrics_store = self.auditor.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_COUNT,
            &format_help!(
                "Total number of attempted DORA exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_COUNT,
            &format_help!(
                "Total number of attempted Inform exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_COUNT,
            &format_help!(
                "Total number of attempted Renew exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_COUNT,
            &format_help!(
                "Total number of attempted Rebind exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_COUNT,
            &format_help!(
                "Total number of attempted Release messages in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
            &format_help!(
                "Percentage of attempted DORA exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
            &format_help!(
                "Percentage of attempted Inform exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
            &format_help!(
                "Percentage of attempted Renew exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
            &format_help!(
                "Percentage of attempted Rebind exchanges in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
            &format_help!(
                "Percentage of attempted Release messages in all exchanges.",
                self.auditor.metric_scope
            ),
            MetricValue::Float64Value(Default::default()),
        ));
    }
}

impl CollectMetrics for DHCPv4SpectrumTotalAuditor {
    fn collect_metrics(&self) {
        let mut metrics_store = self.auditor.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_COUNT,
            MetricValue::Int64Value(
                self.auditor
                    .exchange_count
                    .counter(METRIC_INDEX_ATTEMPTED_DORA),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_COUNT,
            MetricValue::Int64Value(
                self.auditor
                    .exchange_count
                    .counter(METRIC_INDEX_ATTEMPTED_INFORM),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_COUNT,
            MetricValue::Int64Value(
                self.auditor
                    .exchange_count
                    .counter(METRIC_INDEX_ATTEMPTED_RENEW),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_COUNT,
            MetricValue::Int64Value(
                self.auditor
                    .exchange_count
                    .counter(METRIC_INDEX_ATTEMPTED_REBIND),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_COUNT,
            MetricValue::Int64Value(
                self.auditor
                    .exchange_count
                    .counter(METRIC_INDEX_ATTEMPTED_RELEASE),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_DORA),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_INFORM),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_RENEW),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_REBIND),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_RELEASE),
            ),
        );
    }
}

/// An auditor counting different kinds of DHCPv4 transactions.
///
/// # Transaction Types
///
/// The auditor distinguishes between the following transaction types:
///
/// - `DORA`: Discover, Offer, Request, Ack
/// - `Inform`: Inform, Ack
/// - `Renew`: Renew, Ack
/// - `Rebind`: Renew (without server identifier), Ack
/// - `Release`: Release
///
/// # Profiles
///
/// This auditor is used for analyzing live packet streams or capture files
/// when the metrics are periodically displayed during the analysis.
///
#[derive(AuditProfileCheck, CreateAuditor, Debug, DHCPv4TransactionAuditorWithMetrics)]
#[profiles(AuditProfile::LiveStreamFull, AuditProfile::PcapStreamFull)]
pub struct DHCPv4SpectrumStreamAuditor {
    auditor: DHCPv4SpectrumAuditor<PercentSMA<5>>,
}

impl DHCPv4SpectrumStreamAuditor {
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
            auditor: DHCPv4SpectrumAuditor::new(
                metrics_store,
                MetricScope::Moving(config_context.read().unwrap().global.sampling_window_size),
            ),
        }
    }
}

impl DHCPv4TransactionAuditor for DHCPv4SpectrumStreamAuditor {
    fn audit(&mut self, transaction: &mut DHCPv4Transaction) {
        self.auditor.audit(transaction)
    }
}

impl InitMetrics for DHCPv4SpectrumStreamAuditor {
    fn init_metrics(&self) {
        self.auditor.init_metrics()
    }
}

impl CollectMetrics for DHCPv4SpectrumStreamAuditor {
    fn collect_metrics(&self) {
        let mut metrics_store = self.auditor.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_DORA),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_INFORM),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_RENEW),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_REBIND),
            ),
        );
        metrics_store.set_metric_value(
            METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
            MetricValue::Float64Value(
                self.auditor
                    .exchange_count
                    .percentage(METRIC_INDEX_ATTEMPTED_RELEASE),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;
    use crate::{
        auditor::common::DHCPv4TransactionCacheError,
        proto::{dhcp::v4::*, tests::common::TestPacket},
    };

    use endure_lib::{
        auditor::AuditConfigContext, metric::MetricsStore, time_wrapper::TimeWrapper,
    };
    use std::net::Ipv4Addr;

    #[rstest]
    #[case(
        &AuditProfile::LiveStreamFull,
        false
    )]
    #[case(
        &AuditProfile::PcapStreamFull,
        false
    )]
    #[case(
        &AuditProfile::PcapFinalFull,
        true
    )]
    fn spectrum_total_auditor_profiles(#[case] profile: &AuditProfile, #[case] expected: bool) {
        assert_eq!(
            DHCPv4SpectrumTotalAuditor::has_audit_profile(profile),
            expected,
            "incorrect profile support for {:?}",
            profile
        );
    }

    struct TransactionFixture {
        inner_transaction: DHCPv4Transaction,
    }

    impl TransactionFixture {
        fn new() -> Self {
            Self {
                inner_transaction: DHCPv4Transaction::new(),
            }
        }

        fn insert(
            &mut self,
            message_type: MessageType,
            server_id: Option<Ipv4Addr>,
        ) -> Result<(), DHCPv4TransactionCacheError> {
            let mut packet = TestPacket::new_dhcp_packet_with_message_type(message_type);
            if let Some(server_id) = server_id {
                packet = packet.append(&[
                    OPTION_CODE_SERVER_IDENTIFIER,
                    4,
                    server_id.octets()[0],
                    server_id.octets()[1],
                    server_id.octets()[2],
                    server_id.octets()[3],
                ]);
            }
            let packet = ReceivedPacket::new(packet.get()).into_shared_parsable();
            let wrapped_packet = TimeWrapper::from_timeval(
                libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                packet,
            );
            self.inner_transaction.insert(wrapped_packet)
        }
    }

    #[fixture]
    fn transaction() -> TransactionFixture {
        TransactionFixture::new()
    }

    #[rstest]
    #[case(
        MessageType::Discover,
        Some(MessageType::Offer),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
        None
    )]
    #[case(
        MessageType::Discover,
        Some(MessageType::Request),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
        None
    )]
    #[case(
        MessageType::Inform,
        Some(MessageType::Ack),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
        None
    )]
    #[case(
        MessageType::Request,
        Some(MessageType::Ack),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
        Some(Ipv4Addr::new(192, 168, 1, 1))
    )]
    #[case(
        MessageType::Request,
        Some(MessageType::Nak),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
        None
    )]
    #[case(
        MessageType::Release,
        None,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_COUNT,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
        None
    )]
    fn spectrum_total_auditor_audit(
        mut transaction: TransactionFixture,
        #[case] first_message: MessageType,
        #[case] second_message: Option<MessageType>,
        #[case] expected_count_metric: &str,
        #[case] expected_percentage_metric: &str,
        #[case] server_id: Option<Ipv4Addr>,
    ) {
        // Instantiate the auditor.
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor =
            DHCPv4SpectrumTotalAuditor::create_auditor(&metrics_store, &config_context);

        // Sequentially append the messages to the transaction and ensure
        // that the metrics are updated only once. The second message is
        // not appended to the iterator if it is None.
        let messages: Vec<_> = std::iter::once(first_message)
            .chain(second_message)
            .collect();
        for message in messages {
            // Insert the packet into the transaction.
            assert!(transaction.insert(message, server_id).is_ok());

            // Audit the transaction.
            auditor.audit(&mut transaction.inner_transaction);
            auditor.collect_metrics();

            // Assertions.
            let metrics_store_ref = metrics_store.read().unwrap();
            assert_eq!(
                1,
                metrics_store_ref.get_metric_value_unwrapped::<i64>(expected_count_metric),
            );
            assert_eq!(
                100.0,
                metrics_store_ref.get_metric_value_unwrapped::<f64>(expected_percentage_metric)
            );
        }
    }

    #[rstest]
    #[case(
        &AuditProfile::LiveStreamFull,
        true
    )]
    #[case(
        &AuditProfile::PcapStreamFull,
        true
    )]
    #[case(
        &AuditProfile::PcapFinalFull,
        false
    )]
    fn spectrum_stream_auditor_profiles(#[case] profile: &AuditProfile, #[case] expected: bool) {
        assert_eq!(
            DHCPv4SpectrumStreamAuditor::has_audit_profile(profile),
            expected,
            "incorrect profile support for {:?}",
            profile
        );
    }

    #[rstest]
    #[case(
        MessageType::Discover,
        Some(MessageType::Offer),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
        None
    )]
    #[case(
        MessageType::Discover,
        Some(MessageType::Request),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_DORA_PERCENT,
        None
    )]
    #[case(
        MessageType::Inform,
        Some(MessageType::Ack),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_INFORM_PERCENT,
        None
    )]
    #[case(
        MessageType::Request,
        Some(MessageType::Ack),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RENEW_PERCENT,
        Some(Ipv4Addr::new(192, 168, 1, 1))
    )]
    #[case(
        MessageType::Request,
        Some(MessageType::Nak),
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_REBIND_PERCENT,
        None
    )]
    #[case(
        MessageType::Release,
        None,
        METRIC_DHCPV4_SPECTRUM_ATTEMPTED_RELEASE_PERCENT,
        None
    )]
    fn spectrum_stream_auditor_audit(
        mut transaction: TransactionFixture,
        #[case] first_message: MessageType,
        #[case] second_message: Option<MessageType>,
        #[case] expected_percentage_metric: &str,
        #[case] server_id: Option<Ipv4Addr>,
    ) {
        // Instantiate the auditor.
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor =
            DHCPv4SpectrumStreamAuditor::create_auditor(&metrics_store, &config_context);

        // Sequentially append the messages to the transaction and ensure
        // that the metrics are updated only once. The second message is
        // not appended to the iterator if it is None.
        let messages: Vec<_> = std::iter::once(first_message)
            .chain(second_message)
            .collect();
        for message in messages {
            assert!(transaction.insert(message, server_id).is_ok());

            // Audit the transaction.
            auditor.audit(&mut transaction.inner_transaction);
            auditor.collect_metrics();

            // Assertions.
            let metrics_store_ref = metrics_store.read().unwrap();
            assert_eq!(
                100.0,
                metrics_store_ref.get_metric_value_unwrapped::<f64>(expected_percentage_metric)
            );
        }
    }
}
