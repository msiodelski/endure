//! `dhcp::v4` is a module providing DHCPv4 message parsing capabilities.
//!
//! The DHCPv4 protocol described in <https://www.ietf.org/rfc/rfc2131.html>
//! has been built on top of the BOOTP protocol. It reuses its message structures
//! extending them with the DHCP options carrying additional configuration data.
//! This module internally calls the [crate::proto::bootp] module to parse the
//! fixed fields of the DHCPv4 messages.
//!
//! This module provides functions to parse DHCPv4 options carried in the messages.

use std::net::Ipv4Addr;

use crate::proto::{bootp::{self, HAddr}, buffer::{BufferError, ClampedNumber}};

/// Raw packet state.
///
/// It is a default state of the received DHCPv4 packets. A packet in this
/// state includes an unparsed buffer. The packet must be converted into the
/// parsable state with the [ReceivedPacket::into_parsable] to parse the
/// packet.
struct RawState;

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
struct PartiallyParsedState<'a> {
    bootp: bootp::ReceivedPacket<'a, bootp::PartiallyParsedState<'a>>,
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
/// explicitly transitioned to the [PartiallyParsedState] before parsing and
/// accessing the named data fields carried in the packet.
pub struct ReceivedPacket<'a, State> {
    /// Unparsed packet data.
    data: &'a[u8],
    /// Packet state.
    state: State
}

/// A structure representing an inbound DHCP option.
#[derive(Clone, Copy)]
pub struct ReceivedOption<'a> {
    /// Option code.
    code: u8,
    /// Unparsed option data.
    data: &'a[u8]
}

/// A structure representing the flags field in DHCP packet.
pub struct Flags {
    /// Raw flags field value.
    flags: u16
}

impl <'a> ReceivedPacket<'a, RawState> {

    /// Creates a new raw packet instance.
    ///
    /// # Parameters
    ///
    /// - `data` is a reference to the buffer holding the packet.
    fn new(data: &'a [u8]) -> ReceivedPacket<'a, RawState> {
        ReceivedPacket {
            data,
            state: RawState,
        }
    }

    /// Converts the packet to the BOOTP packet.
    fn as_bootp(self) -> bootp::ReceivedPacket<'a, bootp::RawState> {
        bootp::ReceivedPacket::new(self.data)
    }

    /// Transitions the packet from the [RawState] to the [PartiallyParsedState].
    fn into_parsable(self) -> ReceivedPacket<'a, PartiallyParsedState<'a>> {
        let bootp = bootp::ReceivedPacket::new(self.data);
        ReceivedPacket::<'a, PartiallyParsedState> {
            data: self.data,
            state: PartiallyParsedState::<'a>{
                bootp: bootp.into_parsable(),
            },
        }
    }
}

impl <'a> ReceivedPacket<'a, PartiallyParsedState<'a>> {
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
        self.state.bootp.unused().map(|flags| {
            Flags::new(flags)
        })
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
}

impl Flags {
    /// Creates new instance.
    ///
    /// # Parameters:
    ///
    /// - `flags` is a raw flags value.
    pub fn new(flags: u16) -> Flags {
        Flags {
            flags: flags,
        }
    }

    /// Checks if the broadcast flag (most significant bit) is set.
    pub fn is_broadcast(self) -> bool {
        self.flags & 0x8000 != 0
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::proto::{dhcp::v4::ReceivedPacket, bootp::{HType, OpCode}, tests::common::TestBootpPacket};

    use super::Flags;

    #[test]
    fn flags_broadcast() {
        let flags = Flags::new(1);
        assert!(!flags.is_broadcast());

        let flags = Flags::new(0x8000);
        assert!(flags.is_broadcast())
    }

    #[test]
    fn valid_packet() {
        let test_packet = TestBootpPacket::new();
        let packet = ReceivedPacket::new(&test_packet.get());

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
        let test_packet = TestBootpPacket::new();
        let packet = ReceivedPacket::new(&test_packet.get());

        let mut bootp_packet = packet.as_bootp().into_parsable();
        assert_eq!(bootp_packet.opcode(), Ok(&OpCode::BootReply));
    }
}