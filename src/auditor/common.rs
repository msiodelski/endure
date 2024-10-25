//! `common` module contains common declarations for different auditors.

use std::fmt::Debug;

use endure_lib::capture::PacketWrapper;

use crate::proto::dhcp::v4;

/// Capture and analysis profiles.
///
/// A profile defines a collection of auditors used for the analysis. Some
/// of the auditors are not suitable for analyzing the capture files, others
/// are not suitable for analyzing the live packet streams. Predefined profiles
/// differentiate between these cases. The profiles can also select specific
/// auditors aimed at diagnosing a certain set of issues.
#[derive(PartialEq)]
pub enum AuditProfile {
    /// Enable all auditors, capture traffic from interface and analyze
    /// using moving average window.
    LiveStreamFull,
    /// Enable all auditors, analyze a capture file with moving average window.
    PcapStreamFull,
    /// Enable all auditors, analyze a capture file and compute the metrics from
    /// the entire capture.
    PcapFinalFull,
}

/// A trait that must be implemented by auditors running checks on unparsed
/// packets.
///
/// An example auditor implementing this trait is the one that gathers
/// timestamps of the received packets (i.e., [`super::packet_time::PacketTimeAuditor`]).
pub trait GenericPacketAuditor: Debug + Send + Sync {
    /// Runs an audit on the received packet.
    ///
    /// The audit is specific to the given auditor implementing this
    /// trait. The auditor maintains some specific metrics gathered
    /// from the constant analysis of the received packets. It may
    /// discard some of the packets that don't meet the audit criteria.
    ///
    /// # Parameters
    ///
    /// - `packet` - a packet wrapper holding packet metadata.
    fn audit(&mut self, packet: &PacketWrapper);

    /// Collects metrics from the auditor in the metrics store.
    ///
    /// This function is called by the [`crate::analyzer::Analyzer`] for each
    /// auditor. The auditor writes its metrics into the metrics store.
    ///
    fn collect_metrics(&mut self);
}

/// A trait that must be implemented by each DHCPv4 auditor.
///
/// The [`crate::analyzer::Analyzer`] calls the [`DHCPv4PacketAuditor::audit`]
/// function for each received BOOTP packet. The auditor runs specialized
/// checks on the packet and updates its local state and maintained
/// metrics. The [`crate::analyzer::Analyzer`] can call
/// [`DHCPv4PacketAuditor::collect_metrics`] to gather the metrics from the
/// auditor periodically.
pub trait DHCPv4PacketAuditor: Debug + Send + Sync {
    /// Runs an audit on the received packet.
    ///
    /// The audit is specific to the given auditor implementing this
    /// trait. The auditor maintains some specific metrics gathered
    /// from the constant analysis of the received packets. It may
    /// discard some of the packets that don't meet the audit criteria.
    ///
    /// For example: an auditor checking client retransmissions should
    /// ignore the replies from the server and return immediately.
    ///
    /// # Parameters
    ///
    /// - `packet` - a partially parsed `DHCPv4` or `BOOTP` packet to be audited
    fn audit(&mut self, packet: &mut v4::SharedPartiallyParsedPacket);

    /// Collects metrics from the auditor in the metrics store.
    ///
    /// This function is called by the [`crate::analyzer::Analyzer`] for each
    /// auditor. The auditor writes its metrics into the metrics store.
    ///
    fn collect_metrics(&mut self);
}

/// A trait implemented by the auditors checking if they should be executed
/// for the specified [`AuditProfile`].
pub trait AuditProfileCheck {
    /// Checks if the auditor should be run for the specified profile.
    fn has_audit_profile(audit_profile: &AuditProfile) -> bool;
}
