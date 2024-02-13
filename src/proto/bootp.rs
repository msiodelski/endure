//! `bootp` is a module providing the BOOTP message parsing capabilities.
//!
//! The BOOTP protocol has been described in the <https://www.rfc-editor.org/rfc/rfc951.html>.
//! The protocol allows a client machine to request an IPv4 address assignment from a server
//! by sending a BOOTREQUEST message over UDP. The DHCPv4 protocol was designed on top of the
//! BOOTP, reusing its fields and extending it with the DHCPv4 options carrying additional
//! client configuration. See <https://www.ietf.org/rfc/rfc2131.html> for the details.
//!
//! This module should be used for processing the BOOTP messages. The [super::dhcp::v4]
//! module should be used for parsing the DHCPv4 messages.
//!
use std::{
    fmt::{self, Display},
    net::Ipv4Addr,
};

use super::buffer::{BufferError, ClampedNumber, ReceiveBuffer};

/// `opcode` position.
pub const OPCODE_POS: u32 = 0;
/// `htype` position.
pub const HTYPE_POS: u32 = 1;
/// `hlen` position.
pub const HLEN_POS: u32 = 2;
/// Ethernet hardware address length (MAC address length).
pub const HLEN_ETHERNET: usize = 6;
/// `hops` position.
pub const HOPS_POS: u32 = 3;
/// `xid` position.
pub const XID_POS: u32 = 4;
/// `secs` position.
pub const SECS_POS: u32 = 8;
/// `unused` field position. It is used to carry the `flags` in DHCPv4.
pub const UNUSED_POS: u32 = 10;
/// `ciaddr` position.
pub const CIADDR_POS: u32 = 12;
/// `yiaddr` position.
pub const YIADDR_POS: u32 = 16;
/// `siaddr` position.
pub const SIADDR_POS: u32 = 20;
/// `giaddr` position.
pub const GIADDR_POS: u32 = 24;
/// `chaddr` position.
pub const CHADDR_POS: u32 = 28;
/// `chaddr` maximum length.
pub const CHADDR_MAX_LEN: usize = 16;
/// `sname` position.
pub const SNAME_POS: u32 = 44;
/// `sname` maximum length.
pub const SNAME_MAX_LEN: usize = 64;
/// `file` position.
pub const FILE_POS: u32 = 108;
/// `file` maximum length.
pub const FILE_MAX_LEN: usize = 128;

/// An enum representing the bootp message types.
///
/// If the parsed message type is neither [OpCode::BootRequest] nor
/// [OpCode::BootReply] it is set to [OpCode::Invalid] with the actual
/// code as an enum parameter.
#[derive(Debug, PartialEq)]
pub enum OpCode {
    /// A request sent to the server.
    BootRequest,
    /// A reply returned by the server to the client.
    BootReply,
    /// An invalid opcode value received in the parsed BOOTP message.
    Invalid(u8),
}

impl From<u8> for OpCode {
    /// Converts to this type from the `opcode` in the parsed message.
    ///
    /// Valid raw values are:
    /// - `1` for `bootrequest`
    /// - `2` for `bootreply`
    ///
    /// All other values are invalid and converted to [OpCode::Invalid].
    fn from(raw_code: u8) -> Self {
        match raw_code {
            1 => OpCode::BootRequest,
            2 => OpCode::BootReply,
            x => OpCode::Invalid(x),
        }
    }
}

/// An enum representing hardware types.
///
/// The most widely used hardware type is Ethernet. Thus, this is the only
/// type having its own item in this enum. All other types are represented
/// by the catch-all [HType::Other].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HType {
    /// Ethernet hardware type (1).
    Ethernet,
    /// All hardware types other than Ethernet.
    Other(u8),
}

impl From<u8> for HType {
    fn from(raw_code: u8) -> Self {
        match raw_code {
            1 => HType::Ethernet,
            x => HType::Other(x),
        }
    }
}

/// A structure representing a hardware address.
///
/// The length of the hardware address depends on the hardware type. Thus,
/// this structure includes both the buffer with an actual address and the
/// hardware type.
pub struct HAddr {
    htype: HType,
    data: Vec<u8>,
}

impl HAddr {
    /// Creates a hardware address instance from a hardware type and a buffer.
    ///
    /// # Parameters
    ///
    /// - `htype` is a hardware type
    /// - `data` is a variable length buffer holding the harware address
    pub fn new(htype: HType, data: Vec<u8>) -> HAddr {
        HAddr { htype, data }
    }

    /// Checks if the hardware address is invalid.
    ///
    /// Currently supported checks are:
    ///
    /// - `ethernet` hardware address must be 6 bytes long.
    ///
    pub fn invalid(&self) -> bool {
        match self.htype {
            HType::Ethernet => self.data.len() != HLEN_ETHERNET,
            HType::Other(_) => false,
        }
    }

    /// Returns the hardware type.
    pub fn htype(&self) -> &HType {
        &self.htype
    }

    /// Returns the hardware address.
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

impl Display for HAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hex: Vec<String> = Vec::new();
        self.data.iter().for_each(|byte| {
            hex.push(format!("{:02x}", byte));
        });
        write!(f, "{}", hex.join(":"))
    }
}

/// Raw packet state.
///
/// It is a default state of the received `bootp` packets. A packet in this
/// state includes an unparsed buffer. The packet must be converted into the
/// parsable state with the [ReceivedPacket::into_parsable] to parse the
/// packet.
pub struct RawState;

/// Partially parsed packet state.
///
/// A received packet must be transitioned to this state with the
/// [ReceivedPacket::into_parsable] before it can be parsed.
///
/// ### Selective Parsing
///
/// It is possible to access individual values in the received `bootp` message
/// without parsing the entire packet. The respective functions of the [ReceivedPacket]
/// access the `bootp` fields at their offsets and cache the read values in the
/// [PartiallyParsedState]. The cached value is returned the next time the same
/// function is called. Selective parsing improves performance when the caller
/// is only interested in accessing the portions of a packet.
pub struct PartiallyParsedState<'a> {
    buffer: ReceiveBuffer<'a>,
    parsed_opcode: Option<OpCode>,
    parsed_htype: Option<HType>,
    parsed_hlen: Option<ClampedNumber<u8>>,
    parsed_hops: Option<u8>,
    parsed_xid: Option<u32>,
    parsed_secs: Option<u16>,
    parsed_unused: Option<u16>,
    parsed_ciaddr: Option<Ipv4Addr>,
    parsed_yiaddr: Option<Ipv4Addr>,
    parsed_siaddr: Option<Ipv4Addr>,
    parsed_giaddr: Option<Ipv4Addr>,
    parsed_chaddr: Option<HAddr>,
    parsed_sname: Option<String>,
    parsed_file: Option<String>,
}

/// A structure representing a received `bootp` packet.
///
/// # State Model
///
/// A received packet's state is represented by a generic data type `State`.
/// It allows for exposing different set of functions depending on the packet
/// state.
///
/// A received packet is initially in the [RawState]. In this state, the packet
/// is unparsed and exposes no data parsing functions. The packet must be
/// explicitly transitioned to the [PartiallyParsedState] before parsing and
/// accessing the named data fields carried in the packet.
pub struct ReceivedPacket<'a, State> {
    /// Unparsed packet data.
    data: &'a [u8],
    /// Packet state.
    state: State,
}

impl<'a> ReceivedPacket<'a, RawState> {
    /// Creates a new raw packet instance.
    ///
    /// # Parameters
    ///
    /// - `data` is a reference to the buffer holding the packet
    pub fn new(data: &'a [u8]) -> ReceivedPacket<'a, RawState> {
        ReceivedPacket {
            data,
            state: RawState,
        }
    }

    /// Transitions the packet from the [RawState] to the [PartiallyParsedState].
    pub fn into_parsable(self) -> ReceivedPacket<'a, PartiallyParsedState<'a>> {
        ReceivedPacket::<'a, PartiallyParsedState> {
            data: self.data,
            state: PartiallyParsedState {
                buffer: ReceiveBuffer::new(self.data),
                parsed_opcode: None,
                parsed_htype: None,
                parsed_hlen: None,
                parsed_hops: None,
                parsed_xid: None,
                parsed_secs: None,
                parsed_unused: None,
                parsed_ciaddr: None,
                parsed_yiaddr: None,
                parsed_siaddr: None,
                parsed_giaddr: None,
                parsed_chaddr: None,
                parsed_sname: None,
                parsed_file: None,
            },
        }
    }
}

impl<'a> ReceivedPacket<'a, PartiallyParsedState<'a>> {
    /// Reads and caches `opcode`.
    pub fn opcode(&mut self) -> Result<&OpCode, BufferError> {
        if self.state.parsed_opcode.is_some() {
            return Ok(self.state.parsed_opcode.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_u8(OPCODE_POS)
            .map(|code| &*self.state.parsed_opcode.insert(OpCode::from(code)))
    }

    /// Reads and caches `htype`.
    pub fn htype(&mut self) -> Result<&HType, BufferError> {
        if self.state.parsed_htype.is_some() {
            return Ok(self.state.parsed_htype.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_u8(HTYPE_POS)
            .map(|htype| &*self.state.parsed_htype.insert(HType::from(htype)))
    }

    /// Reads and caches `hlen`.
    pub fn hlen(&mut self) -> Result<&ClampedNumber<u8>, BufferError> {
        if self.state.parsed_hlen.is_some() {
            return Ok(self.state.parsed_hlen.as_ref().unwrap());
        }
        self.state.buffer.read_u8(HLEN_POS).map(|hlen| {
            &*self
                .state
                .parsed_hlen
                .insert(ClampedNumber::new(1, CHADDR_MAX_LEN as u8, hlen))
        })
    }

    /// Reads and caches `hops`.
    pub fn hops(&mut self) -> Result<u8, BufferError> {
        if self.state.parsed_hops.is_some() {
            return Ok(self.state.parsed_hops.unwrap());
        }
        self.state
            .buffer
            .read_u8(HOPS_POS)
            .map(|hops| *self.state.parsed_hops.insert(hops))
    }

    /// Reads and caches `xid`.
    pub fn xid(&mut self) -> Result<u32, BufferError> {
        if self.state.parsed_xid.is_some() {
            return Ok(self.state.parsed_xid.unwrap());
        }
        self.state
            .buffer
            .read_u32(XID_POS)
            .map(|xid| *self.state.parsed_xid.insert(xid))
    }

    /// Reads and caches `secs`.
    pub fn secs(&mut self) -> Result<u16, BufferError> {
        if self.state.parsed_secs.is_some() {
            return Ok(self.state.parsed_secs.unwrap());
        }
        self.state
            .buffer
            .read_u16(SECS_POS)
            .map(|xid| *self.state.parsed_secs.insert(xid))
    }

    /// Reads and caches `unused` field.
    pub fn unused(&mut self) -> Result<u16, BufferError> {
        if self.state.parsed_unused.is_some() {
            return Ok(self.state.parsed_unused.unwrap());
        }
        self.state
            .buffer
            .read_u16(UNUSED_POS)
            .map(|unused| *self.state.parsed_unused.insert(unused))
    }

    /// Reads and caches `ciaddr`.
    pub fn ciaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        if self.state.parsed_ciaddr.is_some() {
            return Ok(&self.state.parsed_ciaddr.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_ipv4(CIADDR_POS)
            .map(|ciaddr| &*self.state.parsed_ciaddr.insert(ciaddr))
    }

    /// Reads and caches `yiaddr`.
    pub fn yiaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        if self.state.parsed_yiaddr.is_some() {
            return Ok(&self.state.parsed_yiaddr.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_ipv4(YIADDR_POS)
            .map(|yiaddr| &*self.state.parsed_yiaddr.insert(yiaddr))
    }

    /// Reads and caches `siaddr`.
    pub fn siaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        if self.state.parsed_siaddr.is_some() {
            return Ok(&self.state.parsed_siaddr.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_ipv4(SIADDR_POS)
            .map(|siaddr| &*self.state.parsed_siaddr.insert(siaddr))
    }

    /// Reads and caches `giaddr`.
    pub fn giaddr(&mut self) -> Result<&Ipv4Addr, BufferError> {
        if self.state.parsed_giaddr.is_some() {
            return Ok(&self.state.parsed_giaddr.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_ipv4(GIADDR_POS)
            .map(|giaddr| &*self.state.parsed_giaddr.insert(giaddr))
    }

    /// Reads and caches `chaddr`.
    pub fn chaddr(&mut self) -> Result<&HAddr, BufferError> {
        if self.state.parsed_chaddr.is_some() {
            return Ok(&self.state.parsed_chaddr.as_ref().unwrap());
        }
        let htype = self.htype()?.clone();
        let hlen = self.hlen()?.get();
        self.state
            .buffer
            .read_vec(CHADDR_POS, usize::from(hlen))
            .map(|chaddr| &*self.state.parsed_chaddr.insert(HAddr::new(htype, chaddr)))
    }

    /// Reads and caches `sname`.
    pub fn sname(&mut self) -> Result<&String, BufferError> {
        if self.state.parsed_sname.is_some() {
            return Ok(&self.state.parsed_sname.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_null_terminated(SNAME_POS, SNAME_MAX_LEN)
            .map(|sname| &*self.state.parsed_sname.insert(sname))
    }

    /// Reads and caches `file`.
    pub fn file(&mut self) -> Result<&String, BufferError> {
        if self.state.parsed_file.is_some() {
            return Ok(&self.state.parsed_file.as_ref().unwrap());
        }
        self.state
            .buffer
            .read_null_terminated(FILE_POS, FILE_MAX_LEN)
            .map(|file| &*self.state.parsed_file.insert(file))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::proto::bootp::*;
    use crate::proto::tests::common::TestBootpPacket;

    #[test]
    fn display_hardware_address() {
        let haddr = HAddr::new(HType::Ethernet, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!("01:02:03:04:05:06", haddr.to_string())
    }

    #[test]
    fn display_empty_hardware_address() {
        let haddr = HAddr::new(HType::Ethernet, vec![]);
        assert_eq!("", haddr.to_string())
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
        assert_eq!(parsed_packet.unused(), Ok(32768));
        assert_eq!(parsed_packet.ciaddr(), Ok(&Ipv4Addr::new(192, 0, 2, 22)));
        assert_eq!(parsed_packet.yiaddr(), Ok(&Ipv4Addr::new(192, 0, 2, 23)));
        assert_eq!(parsed_packet.siaddr(), Ok(&Ipv4Addr::new(10, 15, 23, 12)));
        assert_eq!(parsed_packet.giaddr(), Ok(&Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(parsed_packet.sname(), Ok(&String::from("foo")));
        assert_eq!(parsed_packet.file(), Ok(&String::from("/tmp/boot")));

        let chaddr = parsed_packet.chaddr();
        assert!(chaddr.is_ok());
        let chaddr = chaddr.unwrap();
        assert!(!chaddr.invalid());
        assert_eq!(*chaddr.htype(), HType::Ethernet);
        assert_eq!(*chaddr.data(), vec![45, 32, 89, 43, 12, 22])
    }

    #[test]
    fn invalid_opcode() {
        let test_packet = TestBootpPacket::new().set(OPCODE_POS, &vec![5]);
        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        assert_eq!(parsed_packet.opcode(), Ok(&OpCode::Invalid(5)));
    }

    #[test]
    fn other_htype() {
        let test_packet = TestBootpPacket::new().set(HTYPE_POS, &vec![244]);
        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        assert_eq!(parsed_packet.htype(), Ok(&HType::Other(244)));
    }

    #[test]
    fn other_chaddr_type() {
        let test_packet = TestBootpPacket::new()
            .set(HTYPE_POS, &vec![2, 4])
            .set(CHADDR_POS, &vec![1, 2, 3, 4]);

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        assert_eq!(parsed_packet.htype(), Ok(&HType::Other(2)));

        let chaddr = parsed_packet.chaddr();
        assert!(chaddr.is_ok());
        let chaddr = chaddr.unwrap();
        assert!(!chaddr.invalid());
        assert_eq!(*chaddr.htype(), HType::Other(2));
        assert_eq!(*chaddr.data(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn too_high_hlen() {
        let test_packet = TestBootpPacket::new().set(HLEN_POS, &vec![20]).set(
            CHADDR_POS,
            &vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        assert_eq!(parsed_packet.htype(), Ok(&HType::Ethernet));

        let chaddr = parsed_packet.chaddr();
        assert!(chaddr.is_ok());
        let chaddr = chaddr.unwrap();
        assert!(chaddr.invalid());
        assert_eq!(*chaddr.htype(), HType::Ethernet);
        assert_eq!(
            *chaddr.data(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn zero_hlen() {
        let test_packet = TestBootpPacket::new().set(HLEN_POS, &vec![0]);

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        assert_eq!(parsed_packet.htype(), Ok(&HType::Ethernet));

        let chaddr = parsed_packet.chaddr();
        assert!(chaddr.is_ok());
        let chaddr = chaddr.unwrap();
        assert!(chaddr.invalid());
        assert_eq!(*chaddr.htype(), HType::Ethernet);
        assert_eq!(*chaddr.data(), vec![45]);
    }

    #[test]
    fn empty_sname() {
        let test_packet = TestBootpPacket::new().set(SNAME_POS, &vec![0; SNAME_MAX_LEN]);

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        let sname = parsed_packet.sname();
        assert!(sname.is_ok());
        let sname = sname.unwrap();
        assert!(sname.is_empty());
    }

    #[test]
    fn too_long_sname() {
        let test_packet = TestBootpPacket::new().set(SNAME_POS, &vec![65; SNAME_MAX_LEN]);

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        let sname = parsed_packet.sname();
        assert!(sname.is_ok());
        let sname = sname.unwrap();
        assert_eq!(sname.len(), 64);
    }

    #[test]
    fn empty_file() {
        let test_packet = TestBootpPacket::new().set(FILE_POS, &vec![0; FILE_MAX_LEN]);

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        let file = parsed_packet.file();
        assert!(file.is_ok());
        let file = file.unwrap();
        assert!(file.is_empty());
    }

    #[test]
    fn too_long_file() {
        let test_packet = TestBootpPacket::new().set(FILE_POS, &vec![65; FILE_MAX_LEN]);

        let packet = ReceivedPacket::new(&test_packet.get());
        let mut parsed_packet = packet.into_parsable();
        let file = parsed_packet.file();
        assert!(file.is_ok());
        let file = file.unwrap();
        assert_eq!(file.len(), FILE_MAX_LEN);
    }
}
