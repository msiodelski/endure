//! `common` is a module with common declarations for different auditors.

use std::fmt::Debug;

use crate::proto::dhcp::v4;

/// Capture and analysis profiles.
#[derive(PartialEq)]
pub enum AuditProfile {
    /// All auditors enabled and online capture.
    LiveStreamAll,
    /// All auditors enabled and pcap analysis.
    PcapAll,
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
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>);

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
