//! `common` module contains common declarations for different auditors.

use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    fmt::Debug,
    sync::Arc,
    time::Instant,
};

use actix_web::cookie::time::Duration;
use endure_lib::{capture::PacketWrapper, time_wrapper::TimeWrapper};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::proto::{
    bootp::HAddr,
    dhcp::v4::{self, MessageType, SharedPartiallyParsedPacket},
};

/// Represents errors returned by the functions storing received packets
/// in the DHCPv4 transaction cache.
#[derive(Debug, Error, PartialEq)]
pub enum DHCPv4TransactionCacheError {
    /// An error returned upon an attempt to read from the packet.
    #[error("error parsing the packet: {details:?}")]
    BufferRead {
        /// Error details.
        details: String,
    },

    /// An error returned upon an attempt to lock the packet for reading
    /// or writing.
    #[error("error locking the packet while updating transaction cache")]
    PacketLock,

    /// An error returned upon an attempt to insert a packet into transaction,
    /// when the packet of this type already exists.
    #[error("packet {message_type:?} already cached in the transaction")]
    PacketExist {
        /// DHCPv4 message type to which the error pertains.
        message_type: v4::MessageType,
    },

    /// An error returned upon an attempt to insert a packet into transaction,
    /// when the packet lacks a DHCPv4 message type.
    #[error("packet lacks message type option")]
    NoMessageType,

    /// An error returned when trying to save a packet in the transaction when
    /// the packet carries unsupported DHCPv4 message type.
    #[error("message type {message_type_code:?} cannot be cached in a transaction")]
    UnsupportedMessageType {
        /// Message type code.
        message_type_code: u8,
    },
}

/// Indicates the type of the transaction.
#[derive(Debug, PartialEq)]
pub enum DHCPv4TransactionKind {
    /// A DHCPDISCOVER/DHCPOFFER exchange.
    ///
    /// A boolean parameter indicates if the DHCPOFFER has been received.
    Discovery(bool),
    /// A 4-way exchange.
    ///
    /// A boolean parameter indicates if the exchange has been completed.
    FourWayExchange(bool),
    /// A 4-way exchange in which the server responded with DHCPNAK.
    FailedFourWayExchange,
    /// A renewal where client sends DHCPREQUEST without earlier sending DHCPDISCOVER.
    Renewal,
    /// A renewal where the server responded with DHCPNAK.
    FailedRenewal,
    /// An DHCPINFORM/DHCPACK exchange.
    InfRequest,
    /// An undetermined exchange kind.
    Undetermined,
}

/// A DHCPv4 transaction maintained by the [`crate::analyzer::Analyzer`].
///
/// It holds DHCPv4 packets grouped into matching exchanges.
/// The packets are typically be matched by `xid`, MAC address,
/// client identifier etc. Grouping packets allows for generating
/// metrics such as packet processing time (the time to generate
/// a response), number of unanswered client requests and many
/// other.
///
/// In the case of the 4-way exchange, all four messages should
/// be recorded in the [`DHCPv4Transaction`] because there is the
/// expectation that the same `xid` is used in all messages.
/// In case of a lease renew or information request only two
/// messages are typically matched and set in the transaction
/// (e.g., `DHCPREQUEST` and `DHCPACK`).
#[derive(Debug, Clone)]
pub struct DHCPv4Transaction {
    /// A timestamp when the transaction instance was created.
    pub created_at: Instant,
    /// A DHCPDISCOVER message sent by the client.
    pub discover: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
    /// A DHCPOFFER message sent by the server.
    pub offer: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
    /// A DHCPREQUEST message sent by the client.
    pub request: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
    /// A DHCPACK message sent by the server.
    pub ack: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
    /// A DHCPNAK message sent by the server.
    pub nak: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
    /// A DHCPINFORM message sent by the client.
    pub inform: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
}

impl DHCPv4Transaction {
    /// Instantiates new [`DHCPv4Transaction`].
    fn new() -> Self {
        Self {
            created_at: Instant::now(),
            discover: None,
            offer: None,
            request: None,
            ack: None,
            nak: None,
            inform: None,
        }
    }

    /// Instantiates the [`DHCPv4Transaction`] and inserts first packet.
    ///
    /// # Parameters
    ///
    /// - `wrapped_packet` a received DHCP packet with a timestamp to be inserted
    ///   into the transaction.
    ///
    /// # Result
    ///
    /// It returns the same errors as [`DHCPv4Transaction::insert`].
    pub fn from_wrapped_packet(
        wrapped_packet: TimeWrapper<SharedPartiallyParsedPacket>,
    ) -> Result<Self, DHCPv4TransactionCacheError> {
        let mut transaction = Self::new();
        transaction.insert(TimeWrapper::from(wrapped_packet))?;
        return Ok(transaction);
    }

    /// Returns the transaction kind based on the received packets.
    ///
    /// The transaction that includes no packets has [`DHCPv4TransactionKind::Undetermined`]
    /// kind. The kind changes depending on the set of packets stored
    /// in the transaction. If the transaction includes a `DHCPDISCOVER`
    /// packet but no `DHCPREQUEST`, it has a [`DHCPv4TransactionKind::Discovery`]
    /// kind. It may change to [`DHCPv4TransactionKind::FourWayExchange`] when
    /// a `DHCPREQUEST` packet is inserted. It remains [`DHCPv4TransactionKind::FourWayExchange`]
    /// if a server response is successful (i.e., the `DHCPACK`) is received.
    /// However, if the `DHCPNAK` is returned instead, the kind changes
    /// to [`DHCPv4TransactionKind::FailedFourWayExchange`]. If the `DHCPINFORM`
    /// message is recorded, and no messages normally belonging to a 4-way
    /// exchange or a renewal, the transaction kind is [`DHCPv4TransactionKind::InfRequest`].
    ///
    /// The transactional auditors decide whether they should take action or
    /// return early based on the transaction kind returned by this function.
    pub fn kind(&self) -> DHCPv4TransactionKind {
        if self.discover.is_some() {
            // It may be a 4-way exchange.
            return match self.request {
                Some(_) => match self.nak {
                    // It is a 4-way exchange already.
                    Some(_) => DHCPv4TransactionKind::FailedFourWayExchange,
                    None => DHCPv4TransactionKind::FourWayExchange(
                        self.ack.is_some() && self.request.is_some() && self.offer.is_some(),
                    ),
                },
                // Possibly just a first packet or an offer too.
                None => DHCPv4TransactionKind::Discovery(self.offer.is_some()),
            };
        }
        if self.request.is_some() {
            // Not a 4-way exchange because there was no DHCPDISCOVER.
            // Probably a renewal. Let's check if successful or not.
            match self.nak {
                Some(_) => return DHCPv4TransactionKind::FailedRenewal,
                None => return DHCPv4TransactionKind::Renewal,
            }
        }
        // Neither a 4-way exchange nor a renewal.
        if self.inform.is_some() {
            // Information request.
            return DHCPv4TransactionKind::InfRequest;
        }
        DHCPv4TransactionKind::Undetermined
    }

    /// Inserts a packet into the transaction.
    ///
    /// # Parameters
    ///
    /// - `packet` a received DHCP packet to be inserted into the transaction.
    ///
    /// # Result
    ///
    /// If the packet with the same message type is already recorded in
    /// the transaction it returns the [`DHCPv4TransactionCacheError::PacketExist`]
    /// error. If the packet lacks the Message Type option, it returns the
    /// [`DHCPv4TransactionCacheError::NoMessageType`] error. When the specified
    /// packet is not transactional (i.e., the receiving party does not respond to
    /// it per the protocol spec) the [`DHCPv4TransactionCacheError::UnsupportedMessageType`]
    /// error is returned.
    pub fn insert(
        &mut self,
        packet: TimeWrapper<SharedPartiallyParsedPacket>,
    ) -> Result<(), DHCPv4TransactionCacheError> {
        let mut locked_packet = packet
            .get()
            .write()
            .map_err(|_| DHCPv4TransactionCacheError::PacketLock {})?;
        let option_msg_type = locked_packet.option_53_message_type().map_err(|err| {
            DHCPv4TransactionCacheError::BufferRead {
                details: err.to_string(),
            }
        })?;
        if option_msg_type.is_none() {
            return Err(DHCPv4TransactionCacheError::NoMessageType {});
        }
        let msg_type = option_msg_type.unwrap().msg_type;
        match msg_type {
            v4::MessageType::Discover => {
                Self::insert_or_err(&mut self.discover, msg_type, packet.clone())?
            }
            v4::MessageType::Offer => {
                Self::insert_or_err(&mut self.offer, msg_type, packet.clone())?
            }
            v4::MessageType::Request => {
                Self::insert_or_err(&mut self.request, msg_type, packet.clone())?
            }
            v4::MessageType::Nak => Self::insert_or_err(&mut self.nak, msg_type, packet.clone())?,
            v4::MessageType::Ack => Self::insert_or_err(&mut self.ack, msg_type, packet.clone())?,
            v4::MessageType::Inform => {
                Self::insert_or_err(&mut self.inform, msg_type, packet.clone())?
            }
            _ => {
                return Err(DHCPv4TransactionCacheError::UnsupportedMessageType {
                    message_type_code: msg_type.into(),
                })
            }
        }
        return Ok(());
    }

    /// Conditionally sets a DHCPv4 packet instance of a given type.
    ///
    /// It is used internally by the [`DHCPv4Transaction::insert`] function.
    ///
    /// # Parameters
    ///
    /// - `existing_packet` is a reference to a set or unset packet instance.
    /// - `message_type` is a DHCPv4 message type.
    /// - `packet` is a reference to the packet to be set.
    ///
    /// # Results
    ///
    /// It returns [`DHCPv4TransactionCacheError::PacketExist`] error if the
    /// packet has been already set.
    fn insert_or_err(
        existing_packet: &mut Option<TimeWrapper<SharedPartiallyParsedPacket>>,
        message_type: MessageType,
        new_packet: TimeWrapper<SharedPartiallyParsedPacket>,
    ) -> Result<(), DHCPv4TransactionCacheError> {
        if existing_packet.is_some() {
            return Err(DHCPv4TransactionCacheError::PacketExist { message_type });
        };
        *existing_packet = Some(new_packet);
        Ok(())
    }
}

/// A lockable pointer to the [`DHCPv4TransactionCache`].
pub type SharedDHCPv4TransactionCache = Arc<RwLock<DHCPv4TransactionCache>>;

/// Container exposing an index for searching stored DHCPv4 transactions.
#[derive(Clone, Debug, Default)]
pub struct DHCPv4TransactionCache {
    chaddr_xid_index: HashMap<(HAddr, u32), DHCPv4Transaction>,
}

impl DHCPv4TransactionCache {
    /// Instantiates new [`DHCPv4TransactionCache`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Converts [`DHCPv4TransactionCache`] to [`SharedDHCPv4TransactionCache`].
    pub fn to_shared(self) -> SharedDHCPv4TransactionCache {
        Arc::new(RwLock::new(self))
    }

    /// Finds an existing transaction and inserts a packet into it, or creates
    /// a new transaction.
    ///
    /// # Parameters
    ///
    /// - `packet` is a received packet instance to be inserted into the transaction.
    ///
    /// # Result
    ///
    /// On success, it returns the transaction instance where the specified packet
    /// belongs. It may be a new transaction or an existing transaction with other
    /// packets in it. If the found transaction already contains a packet of
    /// the inserted packet's type, the [`DHCPv4TransactionCacheError::PacketExist`]
    /// error is returned. The [`DHCPv4TransactionCacheError::BufferRead`] error is
    /// returned when parsing the packet fails. If the packet lacks the Message Type
    /// option, the [`DHCPv4TransactionCacheError::NoMessageType`] is returned.
    pub fn insert(
        &mut self,
        packet: TimeWrapper<SharedPartiallyParsedPacket>,
    ) -> Result<DHCPv4Transaction, DHCPv4TransactionCacheError> {
        // Get the chaddr and xid from the packet. Lock the packet only once
        // and get both values in the and_then() function.
        let (chaddr, xid) = packet
            .get()
            .clone()
            .write()
            .map_err(|_| DHCPv4TransactionCacheError::PacketLock {})
            .and_then(|mut locked_packet| {
                let chaddr = locked_packet
                    .chaddr()
                    .map_err(|err| DHCPv4TransactionCacheError::BufferRead {
                        details: err.to_string(),
                    })?
                    .clone();
                let xid =
                    locked_packet
                        .xid()
                        .map_err(|err| DHCPv4TransactionCacheError::BufferRead {
                            details: err.to_string(),
                        })?;
                return Ok((chaddr, xid));
            })?;

        match self.chaddr_xid_index.entry((chaddr, xid)) {
            Occupied(occupied_entry) => {
                let transaction = occupied_entry.into_mut();
                transaction.insert(TimeWrapper::from(packet))?;
                Ok(transaction.clone())
            }
            Vacant(vacant_entry) => {
                let transaction = DHCPv4Transaction::from_wrapped_packet(packet)?;
                vacant_entry.insert(transaction.clone());
                Ok(transaction)
            }
        }
    }

    /// Removes all transactions older than the specified number of seconds.
    ///
    /// # Parameters
    ///
    /// - `secs` specifies the maximum number of seconds for the transactions
    ///   to be retained in the cache; older transactions are removed.
    pub async fn garbage_collect_expired(&mut self, secs: i64) {
        self.chaddr_xid_index
            .retain(|_, transaction| transaction.created_at.elapsed() < Duration::seconds(secs));
    }
}

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
    fn collect_metrics(&self);
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
    fn collect_metrics(&self);
}

/// A trait that must be implemented by the transactional DHCPv4 auditors.
///
/// The [`crate::analyzer::Analyzer`] calls the [`DHCPv4TransactionAuditor::audit`]
/// for the groups of related packets (queries and responses) called transactions.
/// Such auditors produce the metrics based on the relationships between the
/// client and server messages. For example: such auditors can measure how long it
/// takes to complete a 4-way exchange.
pub trait DHCPv4TransactionAuditor: Debug + Send + Sync {
    /// Runs an audit on the transaction.
    ///
    /// The audit is specific to the given auditor implementing this
    /// trait. The auditor maintains some specific metrics gathered
    /// from the constant analysis of the received packets. It may
    /// discard some of the transactions that don't meet the audit criteria.
    ///
    /// # Parameters
    ///
    /// - `transaction` is a DHCPv4 transaction holding client requests and
    ///   server responses for the particular `xid` (transaction identifier).
    fn audit(&mut self, transaction: &mut DHCPv4Transaction);

    /// Collects metrics from the auditor in the metrics store.
    ///
    /// This function is called by the [`crate::analyzer::Analyzer`] for each
    /// auditor. The auditor writes its metrics into the metrics store.
    ///
    fn collect_metrics(&self);
}

/// A trait implemented by the auditors checking if they should be executed
/// for the specified [`AuditProfile`].
pub trait AuditProfileCheck {
    /// Checks if the auditor should be run for the specified profile.
    fn has_audit_profile(audit_profile: &AuditProfile) -> bool;
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use endure_lib::time_wrapper::TimeWrapper;

    use crate::{
        auditor::common::{DHCPv4Transaction, DHCPv4TransactionCache, DHCPv4TransactionKind},
        proto::{
            bootp::XID_POS,
            dhcp::v4::{MessageType, ReceivedPacket},
            tests::common::TestPacket,
        },
    };

    use std::ops::Sub;

    #[test]
    fn dhcpv4_transaction_four_way_exchange() {
        let mut transaction = DHCPv4Transaction::new();
        assert_eq!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPDISCOVER.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Discover).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Discovery(false), transaction.kind());

        // DHCPOFFER.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Offer).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Discovery(true), transaction.kind());

        // DHCPREQUEST.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Request).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FourWayExchange(false),
            transaction.kind()
        );

        // DHCPACK.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Ack).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FourWayExchange(true),
            transaction.kind()
        );
    }

    #[test]
    fn dhcpv4_transaction_four_way_exchange_out_of_order() {
        let mut transaction = DHCPv4Transaction::new();
        assert_eq!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPDISCOVER.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Discover).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Discovery(false), transaction.kind());

        // DHCPREQUEST.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Request).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FourWayExchange(false),
            transaction.kind()
        );

        // DHCPACK.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Ack).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FourWayExchange(false),
            transaction.kind()
        );

        // DHCPOFFER.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Offer).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FourWayExchange(true),
            transaction.kind()
        );
    }

    #[test]
    fn dhcpv4_transaction_failed_four_way_exchange() {
        let mut transaction = DHCPv4Transaction::new();
        assert_eq!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPDISCOVER.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Discover).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Discovery(false), transaction.kind());

        // DHCPOFFER.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Offer).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Discovery(true), transaction.kind());

        // DHCPREQUEST.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Request).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FourWayExchange(false),
            transaction.kind()
        );

        // DHCPNAK.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Nak).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(
            DHCPv4TransactionKind::FailedFourWayExchange,
            transaction.kind()
        );
    }

    #[test]
    fn dhcpv4_transaction_renew() {
        let mut transaction = DHCPv4Transaction::new();
        assert_eq!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPREQUEST.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Request).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Renewal, transaction.kind());

        // DHCPACK.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Ack).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Renewal, transaction.kind());
    }

    #[test]
    fn dhcpv4_transaction_failed_renew() {
        let mut transaction = DHCPv4Transaction::new();
        assert_eq!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPREQUEST.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Request).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::Renewal, transaction.kind());

        // DHCPNAK.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Nak).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::FailedRenewal, transaction.kind());
    }

    #[test]
    fn dhcpv4_transaction_inf_request() {
        let mut transaction = DHCPv4Transaction::new();
        assert_eq!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPINFORM.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Inform).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::InfRequest, transaction.kind());

        // DHCPACK.
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Ack).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        assert_eq!(DHCPv4TransactionKind::InfRequest, transaction.kind());
    }

    #[test]
    fn dhcpv4_transaction_double_insert() {
        let mut transaction = DHCPv4Transaction::new();
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Inform).get(),
        )
        .into_shared_parsable();
        let result = transaction.insert(TimeWrapper::from(packet.clone()));
        assert!(result.is_ok());

        let result = transaction.insert(TimeWrapper::from(packet.clone()));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "packet Inform already cached in the transaction"
        );
    }

    #[test]
    fn dhcpv4_transaction_cache_insert() {
        let mut cache = DHCPv4TransactionCache::new();
        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Discover).get(),
        )
        .into_shared_parsable();
        let result = cache.insert(TimeWrapper::from(packet));
        assert!(result.is_ok());
        let transaction = result.unwrap();
        assert_eq!(DHCPv4TransactionKind::Discovery(false), transaction.kind());
        assert!(transaction.discover.is_some());

        let packet = ReceivedPacket::new(
            TestPacket::new_dhcp_packet_with_message_type(MessageType::Offer).get(),
        )
        .into_shared_parsable();
        let result = cache.insert(TimeWrapper::from(packet.clone()));
        assert!(result.is_ok());
        let transaction = result.unwrap();
        assert_eq!(DHCPv4TransactionKind::Discovery(true), transaction.kind());
        assert!(transaction.discover.is_some());
        assert!(transaction.offer.is_some());

        let result = cache.insert(TimeWrapper::from(packet.clone()));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dhcpv4_transaction_cache_garbage_collect() {
        let mut cache = DHCPv4TransactionCache::new();
        for i in 0..10 {
            let packet = ReceivedPacket::new(
                TestPacket::new_dhcp_packet_with_message_type(MessageType::Discover)
                    .set(XID_POS, &vec![i, i, i, i])
                    .get(),
            )
            .into_shared_parsable();
            let result = cache.insert(TimeWrapper::from(packet));
            assert!(result.is_ok());
        }
        cache.garbage_collect_expired(100).await;
        assert_eq!(10, cache.chaddr_xid_index.len());

        cache
            .chaddr_xid_index
            .iter_mut()
            .filter(|tuple| tuple.0 .1 % 2 != 0)
            .for_each(|tuple| {
                tuple.1.created_at = tuple.1.created_at.sub(Duration::from_secs(100));
            });
        cache.garbage_collect_expired(80).await;

        assert_eq!(5, cache.chaddr_xid_index.len());
    }
}
