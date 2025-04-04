//! `dhcp::v4` is a module providing DHCPv4 message parsing capabilities.
//!
//! The DHCPv4 protocol described in <https://www.ietf.org/rfc/rfc2131.html>
//! has been built on top of the BOOTP protocol. It reuses its message structures
//! extending them with the DHCP options carrying additional configuration data.
//! This module internally calls the [crate::proto::bootp] module to parse the
//! fixed fields of the DHCPv4 messages.
//!
//! This module provides functions to parse DHCPv4 options carried in the messages.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
    sync::{Arc, RwLock},
};

use thiserror::Error;

use crate::proto::{
    bootp::{self, HAddr, HType},
    buffer::{BufferError, ClampedNumber, ReceiveBuffer},
};

/// Magic cookie position in the packet.
pub const MAGIC_COOKIE_POS: u32 = 236;
/// DHCPv4 options position in the packet.
pub const OPTIONS_POS: u32 = 240;

/// DHCPDISCOVER message code.
pub const MESSAGE_TYPE_DHCPDISCOVER: u8 = 1;
/// DHCPOFFER message code.
pub const MESSAGE_TYPE_OFFER: u8 = 2;
/// DHCPREQUEST message code.
pub const MESSAGE_TYPE_REQUEST: u8 = 3;
/// DHCPDECLINE message code.
pub const MESSAGE_TYPE_DECLINE: u8 = 4;
/// DHCPACK message code.
pub const MESSAGE_TYPE_ACK: u8 = 5;
/// DHCPNAK message code.
pub const MESSAGE_TYPE_NAK: u8 = 6;
/// DHCPRELEASE message code.
pub const MESSAGE_TYPE_RELEASE: u8 = 7;
/// DHCPINFORM message code.
pub const MESSAGE_TYPE_INFORM: u8 = 8;
/// DHCPFORCERENEW message code.
pub const MESSAGE_TYPE_FORCERENEW: u8 = 9;
/// DHCPLEASEQUERY message code.
pub const MESSAGE_TYPE_LEASEQUERY: u8 = 10;
/// DHCPLEASEUNASSIGNED message code.
pub const MESSAGE_TYPE_LEASEUNASSIGNED: u8 = 11;
/// DHCPLEASEUNKNOWN message code.
pub const MESSAGE_TYPE_LEASEUNKNOWN: u8 = 12;
/// DHCPLEASEACTIVE message code.
pub const MESSAGE_TYPE_LEASEACTIVE: u8 = 13;
/// DHCPBULKLEASEQUERY message code.
pub const MESSAGE_TYPE_BULKLEASEQUERY: u8 = 14;
/// DHCPLEASEQUERYDONE message code.
pub const MESSAGE_TYPE_LEASEQUERYDONE: u8 = 15;
/// DHCPACTIVELEASEQUERY message code.
pub const MESSAGE_TYPE_ACTIVELEASEQUERY: u8 = 16;
/// DHCPLEASEQUERYSTATUS message code.
pub const MESSAGE_TYPE_LEASEQUERYSTATUS: u8 = 17;
/// DHCPTLS message code.
pub const MESSAGE_TYPE_TLS: u8 = 18;

/// Pad option code.
pub const OPTION_CODE_PAD: u8 = 0;
/// DHCP Message Type option code.
pub const OPTION_CODE_DHCP_MESSAGE_TYPE: u8 = 53;
/// Server Identifier option code.
pub const OPTION_CODE_SERVER_IDENTIFIER: u8 = 54;
/// Parameter Request List option code.
pub const OPTION_CODE_PARAMETER_REQUEST_LIST: u8 = 55;
/// Client Identifier option code.
pub const OPTION_CODE_CLIENT_IDENTIFIER: u8 = 61;
/// End option code.
pub const OPTION_CODE_END: u8 = 255;

/// Represents errors returned by the functions parsing DHCP options.
#[derive(Debug, Error, PartialEq)]
pub enum OptionParseError {
    /// An error returned upon an attempt to read from the buffer when the
    /// read position is out of bounds or when the buffer is too short.
    #[error("error reading option data from the packet: {details:?}")]
    BufferRead {
        /// Error details.
        details: String,
    },
    /// An error returned when parsed option is truncated.
    #[error("error parsing truncated option: {option_code:?}, data length: {data_length:?}")]
    Truncated {
        /// Option code.
        option_code: u8,
        /// Received option data length.
        data_length: usize,
    },
}

/// A structure representing an inbound DHCP option.
#[derive(Clone, Debug)]
pub struct ReceivedOption {
    /// Option code.
    code: u8,
    /// Unparsed option data.
    data: Vec<u8>,
}

impl ReceivedOption {
    /// Creates new option instance.
    ///
    /// # Parameters:
    ///
    /// - `code` is an option code.
    /// - `data` is the option payload.
    pub fn new(code: u8, data: &[u8]) -> Self {
        Self {
            code,
            data: data.to_vec(),
        }
    }
}

/// An enum representing the DHCP message types.
///
/// If the parsed message type is unknown, it is set to [`MessageType::Unknown`]
/// with the actual code as an enum parameter.
///
/// See <https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml>
/// for the currently defined message types.
#[derive(Debug, PartialEq)]
pub enum MessageType {
    /// DHCPDISCOVER message.
    Discover,
    /// DHCPOFFER message.
    Offer,
    /// DHCPREQUEST message.
    Request,
    /// DHCPDECLINE message.
    Decline,
    /// DHCPACK message.
    Ack,
    /// DHCPNAK message.
    Nak,
    /// DHCPRELEASE message.
    Release,
    /// DHCPINFORM message.
    Inform,
    /// DHCPFORCERENEW message.
    ForceRenew,
    /// DHCPLEASEQUERY message.
    LeaseQuery,
    /// DHCPLEASEUNASSIGNED message.
    LeaseUnassigned,
    /// DHCPLEASEUNKNOWN message.
    LeaseUnknown,
    /// DHCPLEASEACTIVE message.
    LeaseActive,
    /// DHCPLEASEQUERY message.
    BulkLeaseQuery,
    /// DHCPLEASEQUERYDONE message.
    LeaseQueryDone,
    /// DHCPACTIVELEASEQUERY message.
    ActiveLeaseQuery,
    /// DHCPLEASEQUERYSTATUS message.
    LeaseQueryStatus,
    /// DHCPTLS message.
    Tls,
    /// Unknown DHCP message type.
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(raw_code: u8) -> Self {
        match raw_code {
            MESSAGE_TYPE_DHCPDISCOVER => MessageType::Discover,
            MESSAGE_TYPE_OFFER => MessageType::Offer,
            MESSAGE_TYPE_REQUEST => MessageType::Request,
            MESSAGE_TYPE_DECLINE => MessageType::Decline,
            MESSAGE_TYPE_ACK => MessageType::Ack,
            MESSAGE_TYPE_NAK => MessageType::Nak,
            MESSAGE_TYPE_RELEASE => MessageType::Release,
            MESSAGE_TYPE_INFORM => MessageType::Inform,
            MESSAGE_TYPE_FORCERENEW => MessageType::ForceRenew,
            MESSAGE_TYPE_LEASEQUERY => MessageType::LeaseQuery,
            MESSAGE_TYPE_LEASEUNASSIGNED => MessageType::LeaseUnassigned,
            MESSAGE_TYPE_LEASEUNKNOWN => MessageType::LeaseUnknown,
            MESSAGE_TYPE_LEASEACTIVE => MessageType::LeaseActive,
            MESSAGE_TYPE_BULKLEASEQUERY => MessageType::BulkLeaseQuery,
            MESSAGE_TYPE_LEASEQUERYDONE => MessageType::LeaseQueryDone,
            MESSAGE_TYPE_ACTIVELEASEQUERY => MessageType::ActiveLeaseQuery,
            MESSAGE_TYPE_LEASEQUERYSTATUS => MessageType::LeaseQueryStatus,
            MESSAGE_TYPE_TLS => MessageType::Tls,
            x => MessageType::Unknown(x),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(val: MessageType) -> Self {
        match val {
            MessageType::Discover => MESSAGE_TYPE_DHCPDISCOVER,
            MessageType::Offer => MESSAGE_TYPE_OFFER,
            MessageType::Request => MESSAGE_TYPE_REQUEST,
            MessageType::Decline => MESSAGE_TYPE_DECLINE,
            MessageType::Ack => MESSAGE_TYPE_ACK,
            MessageType::Nak => MESSAGE_TYPE_NAK,
            MessageType::Release => MESSAGE_TYPE_RELEASE,
            MessageType::Inform => MESSAGE_TYPE_INFORM,
            MessageType::ForceRenew => MESSAGE_TYPE_FORCERENEW,
            MessageType::LeaseQuery => MESSAGE_TYPE_LEASEQUERY,
            MessageType::LeaseUnassigned => MESSAGE_TYPE_LEASEUNASSIGNED,
            MessageType::LeaseUnknown => MESSAGE_TYPE_LEASEUNKNOWN,
            MessageType::LeaseActive => MESSAGE_TYPE_LEASEACTIVE,
            MessageType::BulkLeaseQuery => MESSAGE_TYPE_BULKLEASEQUERY,
            MessageType::LeaseQueryDone => MESSAGE_TYPE_LEASEQUERYDONE,
            MessageType::ActiveLeaseQuery => MESSAGE_TYPE_ACTIVELEASEQUERY,
            MessageType::LeaseQueryStatus => MESSAGE_TYPE_LEASEQUERYSTATUS,
            MessageType::Tls => MESSAGE_TYPE_TLS,
            MessageType::Unknown(x) => x,
        }
    }
}

/// Parsed option 53 (DHCP Message Type).
///
///  See `<https://datatracker.ietf.org/doc/html/rfc2132#section-9.6>`.
#[derive(Debug)]
pub struct OptionMessageType {
    /// DHCP message type.
    pub msg_type: MessageType,
}

impl OptionMessageType {
    /// Creates new option 53 instance.
    ///
    /// # Parameter
    ///
    /// - `msg_type` is the DHCP message type carried in the option
    pub fn new(msg_type: MessageType) -> Self {
        Self { msg_type }
    }
}

/// Parsed option 61 (Client Identifier).
///
/// See `<https://datatracker.ietf.org/doc/html/rfc2132#section-9.14>`.
#[derive(Debug, PartialEq)]
pub struct OptionClientIdentifier {
    /// Client identifier type.
    pub identifier_type: HType,
    /// Client identifier.
    pub identifier: Vec<u8>,
}

impl OptionClientIdentifier {
    /// Creates new option 61 instance.
    ///
    /// # Parameters
    ///
    /// - `identifier_type` is the identifier type carried in the first
    ///   byte of the option payload
    /// - `identifier` is the actual client identifier
    pub fn new(identifier_type: HType, identifier: &[u8]) -> Self {
        Self {
            identifier_type,
            identifier: identifier.to_vec(),
        }
    }
}

/// A structure representing the flags field in DHCP packet.
pub struct Flags {
    /// Raw flags field value.
    flags: u16,
}

impl Flags {
    /// Creates new instance.
    ///
    /// # Parameters:
    ///
    /// - `flags` is a raw flags value.
    pub fn new(flags: u16) -> Flags {
        Flags { flags }
    }

    /// Checks if the broadcast flag (most significant bit) is set.
    pub fn is_broadcast(self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// Raw packet state.
///
/// It is a default state of the received DHCPv4 packets. A packet in this
/// state includes an unparsed buffer. The packet must be converted into the
/// parsable state with the [ReceivedPacket::into_parsable] to parse the
/// packet.
pub struct RawState {
    /// Unparsed packet data.
    data: Vec<u8>,
}

/// Partially parsed packet state.
///
/// A received packet must be transitioned to this state with the
/// [ReceivedPacket::into_parsable] before it can be parsed.
///
/// ### Selective Parsing
///
/// It is possible to access individual values in the received DHCP message
/// without parsing the entire packet. The respective functions of the [ReceivedPacket]
/// access the DHCP fields at their offsets and cache the read values in the
/// [PartiallyParsedState]. The cached value is returned the next time the same
/// function is called. Selective parsing improves performance when the caller
/// is only interested in accessing the portions of a packet.
#[derive(Clone, Debug)]
pub struct PartiallyParsedState {
    bootp: bootp::ReceivedPacket<bootp::PartiallyParsedState>,
    options: HashMap<u8, ReceivedOption>,
    options_cursor: u32,
}

/// A structure representing a received DHCP packet.
///
/// # State Model
///
/// A received packet's state is represented by a generic data type `State`.
/// It allows for exposing different set of functions depending on the packet
/// state.
///
/// A received packet is initially in the [RawState] state. In this state, the packet
/// is unparsed and exposes no data parsing functions. The packet must be
/// explicitly transitioned to the [`PartiallyParsedState`] before parsing and
/// accessing the named data fields carried in the packet.
#[derive(Clone, Debug)]
pub struct ReceivedPacket<State> {
    /// Packet state.
    state: State,
}

/// A shorthand type for the raw packet.
pub type RawPacket = ReceivedPacket<RawState>;

/// A shorthand type for the partially parsed packet.
pub type PartiallyParsedPacket = ReceivedPacket<PartiallyParsedState>;

/// A shareable and lockable instance of the [`PartiallyParsedPacket`].
pub type SharedPartiallyParsedPacket = Arc<RwLock<PartiallyParsedPacket>>;

impl ReceivedPacket<RawState> {
    /// Creates a new raw packet instance.
    ///
    /// # Parameters
    ///
    /// - `data` is a reference to the buffer holding the packet.
    pub fn new(data: &[u8]) -> ReceivedPacket<RawState> {
        ReceivedPacket {
            state: RawState {
                data: data.to_vec(),
            },
        }
    }

    /// Converts the packet to the BOOTP packet.
    pub fn as_bootp(self) -> bootp::ReceivedPacket<bootp::RawState> {
        bootp::ReceivedPacket::new(&self.state.data)
    }

    /// Transitions the packet from the [`RawState`] to the [`PartiallyParsedState`].
    ///
    /// # Result
    ///
    /// It returns non-shared, non-lockable, parsable packet instance.
    pub fn into_parsable(&self) -> ReceivedPacket<PartiallyParsedState> {
        let bootp = bootp::ReceivedPacket::new(&self.state.data);
        ReceivedPacket::<PartiallyParsedState> {
            state: PartiallyParsedState {
                bootp: bootp.into_parsable(),
                options: HashMap::new(),
                options_cursor: OPTIONS_POS,
            },
        }
    }

    /// Transitions the packet from the [`RawState`] to the [`PartiallyParsedState`].
    ///
    /// # Result
    ///
    /// It returns shared, lockable, parsable packet instance.
    pub fn into_shared_parsable(&self) -> SharedPartiallyParsedPacket {
        Arc::new(RwLock::new(self.into_parsable()))
    }
}

impl From<ReceivedPacket<RawState>> for PartiallyParsedPacket {
    fn from(val: ReceivedPacket<RawState>) -> Self {
        val.into_parsable()
    }
}

impl From<ReceivedPacket<RawState>> for SharedPartiallyParsedPacket {
    fn from(val: ReceivedPacket<RawState>) -> Self {
        val.into_shared_parsable()
    }
}

impl ReceivedPacket<PartiallyParsedState> {
    /// Reads and caches `opcode`.
    pub fn opcode(&mut self) -> Result<&bootp::OpCode, BufferError> {
        self.state.bootp.opcode()
    }

    /// Reads and caches `htype`.
    pub fn htype(&mut self) -> Result<&bootp::HType, BufferError> {
        self.state.bootp.htype()
    }

    /// Reads and caches `hlen`.
    pub fn hlen(&mut self) -> Result<&ClampedNumber<u8>, BufferError> {
        self.state.bootp.hlen()
    }

    /// Reads and caches `hops`.
    pub fn hops(&mut self) -> Result<u8, BufferError> {
        self.state.bootp.hops()
    }

    /// Reads and caches `xid`.
    pub fn xid(&mut self) -> Result<u32, BufferError> {
        self.state.bootp.xid()
    }

    /// Reads and caches `secs`.
    pub fn secs(&mut self) -> Result<u16, BufferError> {
        self.state.bootp.secs()
    }

    /// Reads and caches flags field.
    pub fn flags(&mut self) -> Result<Flags, BufferError> {
        self.state.bootp.unused().map(Flags::new)
    }

    /// Reads and caches `ciaddr`.
    pub fn ciaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        self.state.bootp.ciaddr()
    }

    /// Reads and caches `yiaddr`.
    pub fn yiaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        self.state.bootp.yiaddr()
    }

    /// Reads and caches `siaddr`.
    pub fn siaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        self.state.bootp.siaddr()
    }

    /// Reads and caches `giaddr`.
    pub fn giaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        self.state.bootp.giaddr()
    }

    /// Reads and caches `chaddr`.
    pub fn chaddr(&mut self) -> Result<&HAddr, BufferError> {
        self.state.bootp.chaddr()
    }

    /// Reads and caches `sname`.
    pub fn sname(&mut self) -> Result<&String, BufferError> {
        self.state.bootp.sname()
    }

    /// Reads and caches `file`.
    pub fn file(&mut self) -> Result<&String, BufferError> {
        self.state.bootp.file()
    }

    /// Attempts to read DHCP option from buffer at specified position.
    ///
    /// If the read is successful the `pos` value is increased by the
    /// amount of data read. Otherwise, the `pos` value remains unchanged.
    /// This function does not validate the length or format of the option.
    /// It may, however, return `BufferError` when the decoded option
    /// length goes beyond the size of the buffer.
    ///
    /// # Parameters
    ///
    /// - `buf` is a buffer to read from.
    /// - `pos` is a position in the buffer to start reading.
    fn try_read_option(
        buf: &mut ReceiveBuffer,
        pos: &mut u32,
    ) -> Result<ReceivedOption, BufferError> {
        let parsed_code = buf.read_u8(*pos)?;
        match buf.read_u8(*pos)? {
            // These options have a special format. They only contain the
            // option code and no option length.
            OPTION_CODE_PAD | OPTION_CODE_END => {
                *pos += 1;
                Ok(ReceivedOption::new(parsed_code, &Vec::new()))
            }
            _ => match buf.read_u8(*pos + 1)? {
                0 => {
                    *pos += 1;
                    Ok(ReceivedOption::new(parsed_code, &Vec::new()))
                }
                parsed_len => {
                    let data = buf.read_vec(*pos + 2, parsed_len as usize)?;
                    *pos += data.len() as u32 + 2;
                    Ok(ReceivedOption::new(parsed_code, &data))
                }
            },
        }
    }

    /// Reads and caches a DHCP option from the packet.
    ///
    /// # Parameters
    ///
    /// - `code` is an option code to be returned.
    ///
    /// # Result
    ///
    /// It returns unparsed DHCP option or `None` if such an option
    /// does not exist in the packet.
    pub fn option(&mut self, code: u8) -> Result<Option<ReceivedOption>, BufferError> {
        // We will collect the parsed options while we search for the
        // requested option in this vector. These options will be cached
        // so we don't have to parse them again in case the caller asks
        // for one of them.
        let mut new_options = Vec::<ReceivedOption>::new();
        // Try to find the requested option among already parsed options.
        let result: Option<ReceivedOption> = match self.state.options.entry(code) {
            // Cached option found. Return it.
            Entry::Occupied(occupied_entry) => Some(occupied_entry.into_mut().clone()),
            // Option hasn't been found yet. Let's try to find it.
            Entry::Vacant(vacant_entry) => loop {
                // Read next option from the packet.
                let result = Self::try_read_option(
                    self.state.bootp.buffer(),
                    &mut self.state.options_cursor,
                );
                match result {
                    Ok(option) => {
                        if code == option.code {
                            // The requested option found. Cache it and return.
                            break Some(vacant_entry.insert(option).clone());
                        } else {
                            // This is not the requested option. Let's cache it
                            // and continue searching.
                            new_options.push(option);
                        }
                    }
                    Err(err) => match err {
                        // This error occurs when we have already gone through the
                        // entire packet. It means that the option does not exist.
                        // Let's return None.
                        BufferError::ReadOutOfBounds {
                            read_position: _,
                            read_length: _,
                            buffer_length: _,
                        } => break None,
                        // Other errors should be propagated to the caller.
                        err => return Err(err),
                    },
                }
            },
        };
        // If we fine some options while looking for the requested
        // option they should be moved to the actual cache.
        new_options.into_iter().for_each(|o| {
            self.state.options.insert(o.code, o);
        });
        Ok(result)
    }

    /// Reads a DHCP option from the packet and transforms the returned
    /// [`BufferError`] to [`OptionParseError`].
    ///
    /// It is called internally by the function parsing specific options.
    /// These functions return the [`OptionParseError`] on error.
    ///
    /// # Parameters
    ///
    /// - `code` is an option code to be returned.
    ///
    /// # Result
    ///
    /// Returns unparsed DHCP option or `None` if such an option
    /// does not exist in the packet.
    ///
    /// # Errors
    ///
    /// Returns [`OptionParseError::BufferRead`] if there was an error
    /// reading the option data from the packet.
    fn option_or_parse_error(
        &mut self,
        code: u8,
    ) -> Result<Option<ReceivedOption>, OptionParseError> {
        self.option(code)
            .map_err(|err| OptionParseError::BufferRead {
                details: err.to_string(),
            })
    }

    /// Returns parsed option 53 (DHCP Message Type).
    ///
    /// # Errors
    ///
    /// It returns [`OptionParseError::Truncated`] if the option is shorter
    /// than one byte.
    pub fn option_53_message_type(
        &mut self,
    ) -> Result<Option<OptionMessageType>, OptionParseError> {
        match self.option_or_parse_error(OPTION_CODE_DHCP_MESSAGE_TYPE)? {
            Some(o) => match o.data.len().cmp(&1) {
                Ordering::Less => {
                    // Option length should be 1. Empty option is truncated
                    // and it carries no message type.
                    Err(OptionParseError::Truncated {
                        option_code: OPTION_CODE_DHCP_MESSAGE_TYPE,
                        data_length: o.data.len(),
                    })
                }
                _ => Ok(Some(OptionMessageType::new(MessageType::from(o.data[0])))),
            },
            _ => Ok(None),
        }
    }

    /// Returns parsed option 54 (Server Identifier).
    ///
    /// # Errors
    ///
    /// It returns [`OptionParseError::Truncated`] if the option is shorter
    /// than four bytes.
    pub fn option_54_server_identifier(&mut self) -> Result<Option<Ipv4Addr>, OptionParseError> {
        match self.option_or_parse_error(OPTION_CODE_SERVER_IDENTIFIER)? {
            Some(o) => match o.data.len().cmp(&4) {
                Ordering::Less => Err(OptionParseError::Truncated {
                    option_code: OPTION_CODE_SERVER_IDENTIFIER,
                    data_length: o.data.len(),
                }),
                _ => Ok(Some(Ipv4Addr::new(
                    o.data[0], o.data[1], o.data[2], o.data[3],
                ))),
            },
            _ => Ok(None),
        }
    }
    /// Returns parsed option 61 (Client Identifier).
    ///
    /// # Errors
    ///
    /// It returns [`OptionParseError::Truncated`] if the option is shorter
    /// than two bytes.
    pub fn option_61_client_identifier(
        &mut self,
    ) -> Result<Option<OptionClientIdentifier>, OptionParseError> {
        match self.option_or_parse_error(OPTION_CODE_CLIENT_IDENTIFIER)? {
            Some(o) => match o.data.len().cmp(&2) {
                Ordering::Less => {
                    // Option length should be 2, including client identifier
                    // type and the actual identifier.
                    Err(OptionParseError::Truncated {
                        option_code: OPTION_CODE_CLIENT_IDENTIFIER,
                        data_length: o.data.len(),
                    })
                }
                _ => Ok(Some(OptionClientIdentifier::new(
                    HType::from(o.data[0]),
                    &o.data[1..],
                ))),
            },
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::proto::{
        bootp::{HType, OpCode},
        dhcp::v4::{
            MessageType, ReceivedPacket, MESSAGE_TYPE_ACK, MESSAGE_TYPE_ACTIVELEASEQUERY,
            MESSAGE_TYPE_BULKLEASEQUERY, MESSAGE_TYPE_DECLINE, MESSAGE_TYPE_DHCPDISCOVER,
            MESSAGE_TYPE_FORCERENEW, MESSAGE_TYPE_INFORM, MESSAGE_TYPE_LEASEACTIVE,
            MESSAGE_TYPE_LEASEQUERY, MESSAGE_TYPE_LEASEQUERYDONE, MESSAGE_TYPE_LEASEQUERYSTATUS,
            MESSAGE_TYPE_LEASEUNASSIGNED, MESSAGE_TYPE_LEASEUNKNOWN, MESSAGE_TYPE_NAK,
            MESSAGE_TYPE_OFFER, MESSAGE_TYPE_RELEASE, MESSAGE_TYPE_REQUEST, MESSAGE_TYPE_TLS,
            OPTION_CODE_CLIENT_IDENTIFIER, OPTION_CODE_DHCP_MESSAGE_TYPE, OPTION_CODE_END,
            OPTION_CODE_PARAMETER_REQUEST_LIST, OPTION_CODE_SERVER_IDENTIFIER,
        },
        tests::common::TestPacket,
    };

    use super::{Flags, OptionClientIdentifier};

    #[test]
    fn flags_broadcast() {
        let flags = Flags::new(1);
        assert!(!flags.is_broadcast());

        let flags = Flags::new(0x8000);
        assert!(flags.is_broadcast())
    }

    #[test]
    fn valid_packet() {
        let test_packet = TestPacket::new_valid_bootp_packet();
        let packet = ReceivedPacket::new(test_packet.get());

        let mut parsed_packet = packet.into_parsable();
        assert_eq!(parsed_packet.opcode(), Ok(&OpCode::BootReply));
        assert_eq!(parsed_packet.htype(), Ok(&HType::Ethernet));
        assert_eq!(parsed_packet.hops(), Ok(1));
        assert_eq!(parsed_packet.xid(), Ok(0x43557883));
        assert_eq!(parsed_packet.secs(), Ok(1));
        assert_eq!(parsed_packet.ciaddr(), Ok(&Ipv4Addr::new(192, 0, 2, 22)));
        assert_eq!(parsed_packet.yiaddr(), Ok(&Ipv4Addr::new(192, 0, 2, 23)));
        assert_eq!(parsed_packet.siaddr(), Ok(&Ipv4Addr::new(10, 15, 23, 12)));
        assert_eq!(parsed_packet.giaddr(), Ok(&Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(parsed_packet.sname(), Ok(&String::from("foo")));
        assert_eq!(parsed_packet.file(), Ok(&String::from("/tmp/boot")));

        let flags = parsed_packet.flags();
        assert!(flags.is_ok());
        assert!(flags.unwrap().is_broadcast());

        let chaddr = parsed_packet.chaddr();
        assert!(chaddr.is_ok());
        let chaddr = chaddr.unwrap();
        assert!(!chaddr.invalid());
        assert_eq!(*chaddr.htype(), HType::Ethernet);
        assert_eq!(*chaddr.data(), vec![45, 32, 89, 43, 12, 22])
    }

    #[test]
    fn convert_into_bootp() {
        let test_packet = TestPacket::new_valid_bootp_packet();
        let packet = ReceivedPacket::new(test_packet.get());

        let mut bootp_packet = packet.as_bootp().into_parsable();
        assert_eq!(bootp_packet.opcode(), Ok(&OpCode::BootReply));
    }

    #[test]
    fn message_type_from_number() {
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_DHCPDISCOVER),
            MessageType::Discover
        );
        assert_eq!(MessageType::from(MESSAGE_TYPE_OFFER), MessageType::Offer);
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_REQUEST),
            MessageType::Request
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_DECLINE),
            MessageType::Decline
        );
        assert_eq!(MessageType::from(MESSAGE_TYPE_ACK), MessageType::Ack);
        assert_eq!(MessageType::from(MESSAGE_TYPE_NAK), MessageType::Nak);
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_RELEASE),
            MessageType::Release
        );
        assert_eq!(MessageType::from(MESSAGE_TYPE_INFORM), MessageType::Inform);
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_FORCERENEW),
            MessageType::ForceRenew
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_LEASEQUERY),
            MessageType::LeaseQuery
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_LEASEUNASSIGNED),
            MessageType::LeaseUnassigned
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_LEASEUNKNOWN),
            MessageType::LeaseUnknown
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_LEASEACTIVE),
            MessageType::LeaseActive
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_BULKLEASEQUERY),
            MessageType::BulkLeaseQuery
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_LEASEQUERYDONE),
            MessageType::LeaseQueryDone
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_ACTIVELEASEQUERY),
            MessageType::ActiveLeaseQuery
        );
        assert_eq!(
            MessageType::from(MESSAGE_TYPE_LEASEQUERYSTATUS),
            MessageType::LeaseQueryStatus
        );
        assert_eq!(MessageType::from(MESSAGE_TYPE_TLS), MessageType::Tls);
        assert_eq!(MessageType::from(100), MessageType::Unknown(100));
    }

    #[test]
    fn message_type_into_number() {
        let message_type: u8 = MessageType::Discover.into();
        assert_eq!(MESSAGE_TYPE_DHCPDISCOVER, message_type);

        let message_type: u8 = MessageType::Offer.into();
        assert_eq!(MESSAGE_TYPE_OFFER, message_type);

        let message_type: u8 = MessageType::Request.into();
        assert_eq!(MESSAGE_TYPE_REQUEST, message_type);

        let message_type: u8 = MessageType::Decline.into();
        assert_eq!(MESSAGE_TYPE_DECLINE, message_type);

        let message_type: u8 = MessageType::Ack.into();
        assert_eq!(MESSAGE_TYPE_ACK, message_type);

        let message_type: u8 = MessageType::Nak.into();
        assert_eq!(MESSAGE_TYPE_NAK, message_type);

        let message_type: u8 = MessageType::Release.into();
        assert_eq!(MESSAGE_TYPE_RELEASE, message_type);

        let message_type: u8 = MessageType::Inform.into();
        assert_eq!(MESSAGE_TYPE_INFORM, message_type);

        let message_type: u8 = MessageType::ForceRenew.into();
        assert_eq!(MESSAGE_TYPE_FORCERENEW, message_type);

        let message_type: u8 = MessageType::LeaseQuery.into();
        assert_eq!(MESSAGE_TYPE_LEASEQUERY, message_type);

        let message_type: u8 = MessageType::LeaseUnassigned.into();
        assert_eq!(MESSAGE_TYPE_LEASEUNASSIGNED, message_type);

        let message_type: u8 = MessageType::LeaseUnknown.into();
        assert_eq!(MESSAGE_TYPE_LEASEUNKNOWN, message_type);

        let message_type: u8 = MessageType::LeaseActive.into();
        assert_eq!(MESSAGE_TYPE_LEASEACTIVE, message_type);

        let message_type: u8 = MessageType::BulkLeaseQuery.into();
        assert_eq!(MESSAGE_TYPE_BULKLEASEQUERY, message_type);

        let message_type: u8 = MessageType::LeaseQueryDone.into();
        assert_eq!(MESSAGE_TYPE_LEASEQUERYDONE, message_type);

        let message_type: u8 = MessageType::ActiveLeaseQuery.into();
        assert_eq!(MESSAGE_TYPE_ACTIVELEASEQUERY, message_type);

        let message_type: u8 = MessageType::LeaseQueryStatus.into();
        assert_eq!(MESSAGE_TYPE_LEASEQUERYSTATUS, message_type);

        let message_type: u8 = MessageType::Tls.into();
        assert_eq!(MESSAGE_TYPE_TLS, message_type);
    }

    #[test]
    fn read_option() {
        let test_packet = TestPacket::new_valid_dhcp_packet();
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();

        for _ in [0, 1] {
            let result = packet.option(OPTION_CODE_DHCP_MESSAGE_TYPE);
            assert!(result.is_ok());
            let option = result.unwrap();
            assert!(option.is_some());
            let option = option.unwrap();
            assert_eq!(option.code, OPTION_CODE_DHCP_MESSAGE_TYPE);
            assert_eq!(*option.data, vec![1]);
        }

        let result = packet.option(128);
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_none());

        let result = packet.option(OPTION_CODE_PARAMETER_REQUEST_LIST);
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let option = option.unwrap();
        assert_eq!(option.code, OPTION_CODE_PARAMETER_REQUEST_LIST);
        assert_eq!(*option.data, vec![1, 28, 2, 3, 15, 6, 12]);

        let result = packet.option(OPTION_CODE_END);
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let option = option.unwrap();
        assert_eq!(option.code, OPTION_CODE_END);
        assert!(option.data.is_empty());
    }

    #[test]
    fn read_option_53() {
        let test_packet = TestPacket::new_valid_dhcp_packet();
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();

        let result = packet.option_53_message_type();
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let option = option.unwrap();
        assert_eq!(option.msg_type, MessageType::Discover);
    }

    #[test]
    fn parse_option_53_truncated() {
        let test_packet =
            TestPacket::new_base_dhcp_packet().append(&[OPTION_CODE_DHCP_MESSAGE_TYPE, 0]);
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();
        let result = packet.option_53_message_type();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "error parsing truncated option: 53, data length: 0"
        );
    }

    #[test]
    fn read_option_54() {
        let test_packet =
            TestPacket::new_dhcp_packet_with_server_identifier(Ipv4Addr::new(192, 168, 1, 1));
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();
        assert_eq!(
            packet.option_54_server_identifier().ok().flatten(),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn read_option_54_truncated() {
        let test_packet = TestPacket::new_base_dhcp_packet().append(&[
            OPTION_CODE_SERVER_IDENTIFIER,
            2,
            192,
            168,
        ]);
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();
        let result = packet.option_54_server_identifier();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "error parsing truncated option: 54, data length: 2"
        );
    }

    #[test]
    fn read_option_61() {
        let test_packet = TestPacket::new_valid_dhcp_packet();
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();

        let result = packet.option_61_client_identifier();
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let option = option.unwrap();
        assert_eq!(option.identifier_type, HType::Ethernet);
        assert_eq!(option.identifier, vec![0, 12, 1, 2, 3, 9])
    }

    #[test]
    fn parse_option_61_truncated() {
        let test_packet =
            TestPacket::new_base_dhcp_packet().append(&[OPTION_CODE_CLIENT_IDENTIFIER, 1, 2]);
        let mut packet = ReceivedPacket::new(test_packet.get()).into_parsable();
        let result = packet.option_61_client_identifier();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "error parsing truncated option: 61, data length: 1"
        );
    }

    #[test]
    fn compare_option_61_equal() {
        let client_id_1 = OptionClientIdentifier::new(HType::Ethernet, &[1, 2, 3, 4, 5, 6]);
        let client_id_2 = OptionClientIdentifier::new(HType::Ethernet, &[1, 2, 3, 4, 5, 6]);

        assert_eq!(client_id_1, client_id_2)
    }

    #[test]
    fn compare_option_61_non_equal_types() {
        let client_id_1 = OptionClientIdentifier::new(HType::Ethernet, &[1, 2, 3, 4, 5, 6]);
        let client_id_2 = OptionClientIdentifier::new(HType::Other(3), &[1, 2, 3, 4, 5, 6]);

        assert_ne!(client_id_1, client_id_2)
    }

    #[test]
    fn compare_option_61_non_equal_identifiers() {
        let client_id_1 = OptionClientIdentifier::new(HType::Ethernet, &[1, 2, 3, 4, 5, 6]);
        let client_id_2 = OptionClientIdentifier::new(HType::Ethernet, &[1, 2, 2, 3, 5, 6]);

        assert_ne!(client_id_1, client_id_2)
    }
}
