//! `packet_time` is a module implementing an auditor tracking last packet
//! timestamp.

use super::{
    common::{
        AuditProfile, AuditProfileCheck, GenericPacketAuditor, GenericPacketAuditorWithMetrics,
    },
    metric::METRIC_PACKET_TIME_DATE_TIME,
};
use chrono::{DateTime, Local};
use endure_lib::{
    auditor::{CreateAuditor, SharedAuditConfigContext},
    capture::PacketWrapper,
    metric::{CollectMetrics, InitMetrics, Metric, MetricValue, SharedMetricsStore},
};
use endure_macros::{AuditProfileCheck, CreateAuditor, GenericPacketAuditorWithMetrics};

/// An auditor tracking timestamp of the last analyzed packet.
///
/// # Profiles
///
/// This auditor is used during the `pcap` file analysis. It is not used for
/// the analysis of the captures from the network interface.
///
#[derive(AuditProfileCheck, Clone, CreateAuditor, Debug, GenericPacketAuditorWithMetrics)]
#[profiles(AuditProfile::PcapStreamFull)]
pub struct PacketTimeAuditor {
    metrics_store: SharedMetricsStore,
    packet_time_sec: i64,
    packet_time_usec: u32,
}

impl PacketTimeAuditor {
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
            packet_time_sec: Default::default(),
            packet_time_usec: Default::default(),
        }
    }
}

impl GenericPacketAuditor for PacketTimeAuditor {
    fn audit(&mut self, packet: &PacketWrapper) {
        self.packet_time_sec = packet.header.ts.tv_sec;
        self.packet_time_usec = packet.header.ts.tv_usec as u32;
    }
}

impl InitMetrics for PacketTimeAuditor {
    fn init_metrics(&self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_PACKET_TIME_DATE_TIME,
            "Timestamp of the last analyzed packet.",
            MetricValue::StringValue(Default::default()),
        ));
    }
}

impl CollectMetrics for PacketTimeAuditor {
    fn collect_metrics(&self) {
        if self.packet_time_sec == 0 && self.packet_time_usec == 0 {
            return;
        }
        let timestamp = DateTime::from_timestamp(self.packet_time_sec, self.packet_time_usec);
        if let Some(timestamp) = timestamp {
            let timestamp = DateTime::<Local>::from(timestamp);
            let mut metrics_store = self.metrics_store.write().unwrap();
            metrics_store.set_metric_value(
                METRIC_PACKET_TIME_DATE_TIME,
                MetricValue::StringValue(timestamp.to_rfc3339()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use endure_lib::{
        auditor::{AuditConfigContext, CreateAuditor},
        capture::PacketWrapper,
        metric::{CollectMetrics, MetricsStore},
    };
    use pcap::{Linktype, PacketHeader};

    use crate::auditor::{
        common::{AuditProfile, AuditProfileCheck, GenericPacketAuditor},
        metric::METRIC_PACKET_TIME_DATE_TIME,
        packet_time::PacketTimeAuditor,
    };

    #[test]
    fn packet_time_auditor_profiles() {
        assert!(!PacketTimeAuditor::has_audit_profile(
            &AuditProfile::LiveStreamFull
        ));
        assert!(PacketTimeAuditor::has_audit_profile(
            &AuditProfile::PcapStreamFull
        ));
    }

    #[test]
    fn packet_time_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let config_context = AuditConfigContext::new().to_shared();
        let mut auditor = PacketTimeAuditor::create_auditor(&metrics_store, &config_context);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        // Initially, the packet time should be empty.
        assert!(metrics_store_ref
            .read()
            .unwrap()
            .get_metric_value_unwrapped::<String>(METRIC_PACKET_TIME_DATE_TIME)
            .is_empty());

        let packet = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 1711535347,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::ETHERNET,
        };

        auditor.audit(&packet);
        auditor.collect_metrics();

        // The packet time should have been set.
        assert!(metrics_store_ref
            .read()
            .unwrap()
            .get_metric_value_unwrapped::<String>(METRIC_PACKET_TIME_DATE_TIME)
            .starts_with("2024-03-27"));
    }
}
