//! `packet_time` is a module implementing auditor tracking last packet timestamp.

use super::{
    common::{AuditProfile, AuditProfileCheck, GenericPacketAuditor},
    metric::METRIC_PACKET_TIME_DATE_TIME,
};
use chrono::{DateTime, Local};
use endure_lib::{
    listener::PacketWrapper,
    metric::{FromMetricsStore, InitMetrics, Metric, MetricValue, SharedMetricsStore},
};
use endure_macros::{AuditProfileCheck, FromMetricsStore};

/// An auditor tracking timestamp of the last analyzed packet.
///
/// This auditor is particularly useful in `pcap` file analysis. In live capture
/// case we display report timestamps. In `pcap` case only packet timestamps
/// are available.
#[derive(AuditProfileCheck, Clone, Debug, FromMetricsStore)]
#[profiles(AuditProfile::PcapStreamFull)]
pub struct PacketTimeAuditor {
    metrics_store: SharedMetricsStore,
    packet_time_sec: i64,
    packet_time_usec: u32,
}

impl Default for PacketTimeAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
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

    fn collect_metrics(&mut self) {
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

impl InitMetrics for PacketTimeAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_PACKET_TIME_DATE_TIME,
            "Timestamp of the last analyzed packet.",
            MetricValue::StringValue(Default::default()),
        ));
    }
}

#[cfg(test)]
mod tests {
    use endure_lib::{
        listener::PacketWrapper,
        metric::{FromMetricsStore, MetricsStore},
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
        let mut auditor = PacketTimeAuditor::from_metrics_store(&metrics_store);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        let packet_time_date_time = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_PACKET_TIME_DATE_TIME);
        assert!(packet_time_date_time.is_some());
        assert!(packet_time_date_time
            .unwrap()
            .get_value_unwrapped::<String>()
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

        let packet_time_date_time = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_PACKET_TIME_DATE_TIME);
        assert!(packet_time_date_time.is_some());
        assert!(packet_time_date_time
            .unwrap()
            .get_value_unwrapped::<String>()
            .starts_with("2024-03-27"));
    }
}
