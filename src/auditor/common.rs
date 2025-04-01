//! `common` module contains common declarations for different auditors.

use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    fmt::Debug,
    net::Ipv4Addr,
    sync::Arc,
    time::Instant,
};

use actix_web::cookie::time::Duration;
use endure_lib::{capture::PacketWrapper, metric::CollectMetrics, time_wrapper::TimeWrapper};
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
    /// This kind is set when a DHCPREQUEST was sent following the DHCPDISCOVER,
    /// but neither DHCPACK or DHCPNAK.
    FourWayExchange,
    /// A 4-way exchange in which the server responded with DHCPACK.
    SuccessfulFourWayExchange,
    /// A 4-way exchange in which the server responded with DHCPNAK.
    FailedFourWayExchange,
    /// A renewal when client sends DHCPREQUEST without earlier sending DHCPDISCOVER.
    Renewal,
    /// A renewal when the server responded with DHCPACK.
    SuccessfulRenewal,
    /// A renewal when the server responded with DHCPNAK.
    FailedRenewal,
    /// A DHCPINFORM exchange case when the server has not yet responded.
    InfRequest,
    /// A DHCPINFORM/DHCPACK exchange.
    SuccessfulInfRequest,
    /// A DHCPRELEASE message sent by the client.
    Release,
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
    /// A DHCPRELEASE message sent by the client.
    pub release: Option<TimeWrapper<SharedPartiallyParsedPacket>>,
}

impl DHCPv4Transaction {
    /// Instantiates new [`DHCPv4Transaction`].
    pub fn new() -> Self {
        Self {
            created_at: Instant::now(),
            discover: None,
            offer: None,
            request: None,
            ack: None,
            nak: None,
            inform: None,
            release: None,
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
        match (
            &self.discover,
            &self.offer,
            &self.request,
            &self.ack,
            &self.nak,
            &self.inform,
            &self.release,
        ) {
            (Some(_), _, None, None, None, None, None) => {
                DHCPv4TransactionKind::Discovery(self.offer.is_some())
            }
            (Some(_), _, Some(_), None, None, None, None) => DHCPv4TransactionKind::FourWayExchange,
            (Some(_), _, Some(_), Some(_), None, None, None) => {
                DHCPv4TransactionKind::SuccessfulFourWayExchange
            }
            (Some(_), _, Some(_), None, Some(_), None, None) => {
                DHCPv4TransactionKind::FailedFourWayExchange
            }
            (None, None, Some(_), None, None, None, None) => DHCPv4TransactionKind::Renewal,
            (None, None, Some(_), Some(_), None, None, None) => {
                DHCPv4TransactionKind::SuccessfulRenewal
            }
            (None, None, Some(_), None, Some(_), None, None) => {
                DHCPv4TransactionKind::FailedRenewal
            }
            (None, None, None, None, None, Some(_), None) => DHCPv4TransactionKind::InfRequest,
            (None, None, None, Some(_), None, Some(_), None) => {
                DHCPv4TransactionKind::SuccessfulInfRequest
            }
            (_, _, _, _, _, _, Some(_)) => DHCPv4TransactionKind::Release,
            _ => DHCPv4TransactionKind::Undetermined,
        }
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
            v4::MessageType::Release => {
                Self::insert_or_err(&mut self.release, msg_type, packet.clone())?
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
#[derive(Debug, PartialEq)]
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
}

/// A trait that combines [`GenericPacketAuditor`] and [`CollectMetrics`].
///
/// It is used for storing auditors in collections.
pub trait GenericPacketAuditorWithMetrics: GenericPacketAuditor + CollectMetrics {}

/// A trait that must be implemented by each DHCPv4 auditor.
///
/// The [`crate::analyzer::Analyzer`] calls the [`DHCPv4PacketAuditor::audit`]
/// function for each received BOOTP packet. The auditor runs specialized
/// checks on the packet and updates its local state and maintained
/// metrics.
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
    /// - `source_ip_address` - a source IP address of the packet.
    /// - `dest_ip_address` - a destination IP address of the packet.
    /// - `packet` - a partially parsed `DHCPv4` or `BOOTP` packet to be audited
    fn audit(
        &mut self,
        source_ip_address: &Ipv4Addr,
        dest_ip_address: &Ipv4Addr,
        packet: &mut v4::SharedPartiallyParsedPacket,
    );
}

/// A trait that combines [`DHCPv4PacketAuditor`] and [`CollectMetrics`].
///
/// It is used for storing auditors in collections.
pub trait DHCPv4PacketAuditorWithMetrics: DHCPv4PacketAuditor + CollectMetrics {}

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
}

/// A trait that combines [`DHCPv4TransactionAuditor`] and [`CollectMetrics`].
///
/// It is used for storing auditors in collections.
pub trait DHCPv4TransactionAuditorWithMetrics: DHCPv4TransactionAuditor + CollectMetrics {}

/// A trait implemented by the auditors checking if they should be executed
/// for the specified [`AuditProfile`].
pub trait AuditProfileCheck {
    /// Checks if the auditor should be run for the specified profile.
    fn has_audit_profile(audit_profile: &AuditProfile) -> bool;
}

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use rstest::{fixture, rstest};

    use endure_lib::time_wrapper::TimeWrapper;

    use crate::{
        auditor::common::{DHCPv4Transaction, DHCPv4TransactionCache, DHCPv4TransactionKind},
        proto::{
            bootp::XID_POS,
            dhcp::v4::{MessageType, ReceivedPacket},
            tests::common::TestPacket,
        },
    };

    use super::DHCPv4TransactionCacheError;
    use std::ops::Sub;
    use std::time::Duration;

    struct TransactionFixture {
        inner_transaction: DHCPv4Transaction,
    }

    impl TransactionFixture {
        fn new() -> Self {
            Self {
                inner_transaction: DHCPv4Transaction::new(),
            }
        }

        fn kind(&self) -> DHCPv4TransactionKind {
            self.inner_transaction.kind()
        }

        fn insert(&mut self, message_type: MessageType) -> Result<(), DHCPv4TransactionCacheError> {
            let packet = ReceivedPacket::new(
                TestPacket::new_dhcp_packet_with_message_type(message_type).get(),
            )
            .into_shared_parsable();
            self.inner_transaction.insert(TimeWrapper::from(packet))
        }
    }

    #[fixture]
    fn transaction() -> TransactionFixture {
        let transaction = TransactionFixture::new();
        transaction
    }

    #[rstest]
    fn dhcpv4_transaction_four_way_exchange(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPDISCOVER.
        assert!(transaction.insert(MessageType::Discover).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == false);

        // DHCPOFFER.
        assert!(transaction.insert(MessageType::Offer).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == true);

        // DHCPREQUEST.
        assert!(transaction.insert(MessageType::Request).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::FourWayExchange);

        // DHCPACK.
        assert!(transaction.insert(MessageType::Ack).is_ok());
        assert_matches!(
            transaction.kind(),
            DHCPv4TransactionKind::SuccessfulFourWayExchange
        );
    }

    #[rstest]
    fn dhcpv4_transaction_four_way_exchange_out_of_order(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPDISCOVER.
        assert!(transaction.insert(MessageType::Discover).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == false);

        // DHCPREQUEST.
        assert!(transaction.insert(MessageType::Request).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::FourWayExchange);

        // DHCPACK.
        assert!(transaction.insert(MessageType::Ack).is_ok());
        assert_matches!(
            transaction.kind(),
            DHCPv4TransactionKind::SuccessfulFourWayExchange
        );

        // DHCPOFFER.
        assert!(transaction.insert(MessageType::Offer).is_ok());
        assert_matches!(
            transaction.kind(),
            DHCPv4TransactionKind::SuccessfulFourWayExchange
        );
    }

    #[rstest]
    fn dhcpv4_transaction_failed_four_way_exchange(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPDISCOVER.
        assert!(transaction.insert(MessageType::Discover).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == false);

        // DHCPOFFER.
        assert!(transaction.insert(MessageType::Offer).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == true);

        // DHCPREQUEST.
        assert!(transaction.insert(MessageType::Request).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::FourWayExchange);

        // DHCPNAK.
        assert!(transaction.insert(MessageType::Nak).is_ok());
        assert_matches!(
            transaction.kind(),
            DHCPv4TransactionKind::FailedFourWayExchange
        );
    }

    #[rstest]
    fn dhcpv4_transaction_renew(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPREQUEST.
        assert!(transaction.insert(MessageType::Request).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Renewal);

        // DHCPACK.
        assert!(transaction.insert(MessageType::Ack).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::SuccessfulRenewal);
    }

    #[rstest]
    fn dhcpv4_transaction_failed_renew(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPREQUEST.
        assert!(transaction.insert(MessageType::Request).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Renewal);

        // DHCPNAK.
        assert!(transaction.insert(MessageType::Nak).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::FailedRenewal);
    }

    #[rstest]
    fn dhcpv4_transaction_inf_request(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPINFORM.
        assert!(transaction.insert(MessageType::Inform).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::InfRequest);

        // DHCPACK.
        assert!(transaction.insert(MessageType::Ack).is_ok());
        assert_matches!(
            transaction.kind(),
            DHCPv4TransactionKind::SuccessfulInfRequest
        );
    }

    #[rstest]
    fn dhcpv4_transaction_failed_inf_request(mut transaction: TransactionFixture) {
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);

        // DHCPINFORM.
        assert!(transaction.insert(MessageType::Inform).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::InfRequest);

        // DHCPNAK is unexpected for this transaction type. The transaction type
        // becomes undetermined.
        assert!(transaction.insert(MessageType::Nak).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Undetermined);
    }

    #[rstest]
    fn dhcpv4_transaction_double_insert(mut transaction: TransactionFixture) {
        assert!(transaction.insert(MessageType::Inform).is_ok());
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::InfRequest);

        assert_matches!(
            transaction.insert(MessageType::Inform),
            Err(DHCPv4TransactionCacheError::PacketExist { message_type })
            if message_type == MessageType::Inform
        );
    }

    struct CacheFixture {
        inner_cache: DHCPv4TransactionCache,
    }

    impl CacheFixture {
        fn new() -> Self {
            Self {
                inner_cache: DHCPv4TransactionCache::new(),
            }
        }

        fn insert(
            &mut self,
            message_type: MessageType,
        ) -> Result<DHCPv4Transaction, DHCPv4TransactionCacheError> {
            let packet = ReceivedPacket::new(
                TestPacket::new_dhcp_packet_with_message_type(message_type).get(),
            )
            .into_shared_parsable();
            self.inner_cache.insert(TimeWrapper::from(packet))
        }

        fn insert_with_xid(
            &mut self,
            message_type: MessageType,
            xid: &[u8],
        ) -> Result<DHCPv4Transaction, DHCPv4TransactionCacheError> {
            let packet = ReceivedPacket::new(
                TestPacket::new_dhcp_packet_with_message_type(message_type)
                    .set(XID_POS, xid)
                    .get(),
            )
            .into_shared_parsable();
            self.inner_cache.insert(TimeWrapper::from(packet))
        }
    }

    #[fixture]
    fn cache() -> CacheFixture {
        let cache = CacheFixture::new();
        cache
    }

    #[rstest]
    fn dhcpv4_transaction_cache_insert(mut cache: CacheFixture) {
        let transaction = cache
            .insert(MessageType::Discover)
            .expect("Failed to insert DHCPDISCOVER");
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == false);
        assert!(transaction.discover.is_some());

        let transaction = cache
            .insert(MessageType::Offer)
            .expect("Failed to insert DHCPOFFER");
        assert_matches!(transaction.kind(), DHCPv4TransactionKind::Discovery(offer_received) if offer_received == true);
        assert!(transaction.discover.is_some());
        assert!(transaction.offer.is_some());

        let result = cache.insert(MessageType::Offer);
        assert_matches!(result, Err(DHCPv4TransactionCacheError::PacketExist { message_type }) if message_type == MessageType::Offer);
    }

    #[rstest]
    #[tokio::test]
    async fn dhcpv4_transaction_cache_garbage_collect(mut cache: CacheFixture) {
        // Insert several DHCPDISCOVER packets into the cache with different xid values,
        // so they are treated as different transactions.
        for i in 0..10 {
            _ = cache
                .insert_with_xid(MessageType::Discover, &vec![i, i, i, i])
                .expect("Failed to insert DHCPDISCOVER into cache");
        }
        // Initially, there are no expired transactions, so they should all
        // remain the cache.
        cache.inner_cache.garbage_collect_expired(100).await;
        assert_eq!(10, cache.inner_cache.chaddr_xid_index.len());

        // Expire half of the transactions.
        cache
            .inner_cache
            .chaddr_xid_index
            .iter_mut()
            .filter(|tuple| tuple.0 .1 % 2 != 0)
            .for_each(|tuple| {
                tuple.1.created_at = tuple.1.created_at.sub(Duration::from_secs(100));
            });
        cache.inner_cache.garbage_collect_expired(80).await;

        // After garbage collection, only the expired transactions should be removed.
        assert_eq!(5, cache.inner_cache.chaddr_xid_index.len());
    }
}
