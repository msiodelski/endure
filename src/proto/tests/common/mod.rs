use crate::proto::dhcp::v4::{MessageType, OPTION_CODE_DHCP_MESSAGE_TYPE};

const VALID_BOOTP_PACKET: &'static [u8] = &[
    2, // op (1 byte) = BOOTREPLY
    1, // htype (1 byte) = Ethernet
    6, // hlen (1 byte)
    1, // hops (1 byte)
    67, 85, 120, 131, // xid (4 bytes)
    0, 1, // secs (2 bytes) = 1 s
    128, 0, // reserved (2 bytes)
    192, 0, 2, 22, // ciaddr (4 bytes)
    192, 0, 2, 23, // yiaddr (4 bytes)
    10, 15, 23, 12, // siaddr (4 bytes)
    192, 0, 2, 1, // giaddr (4 bytes)
    45, 32, 89, 43, 12, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // chaddr (16 bytes)
    102, 111, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, // sname (64 bytes)
    47, 116, 109, 112, 47, 98, 111, 111, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, // file (128 bytes) = /tmp/boot
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, // vend (64 bytes)
];

const VALID_DHCP_PACKET: &'static [u8] = &[
    1, // op (1 byte) = BOOTREQUEST
    1, // htype (1 byte) = Ethernet
    6, // hlen (1 byte)
    1, // hops (1 byte)
    0, 0, 0, 5, // xid (4 bytes)
    0, 3, // secs (2 bytes)
    0, 0, // flags (2 bytes)
    0, 0, 0, 0, // ciaddr (4 bytes)
    0, 0, 0, 0, // yiaddr (4 bytes)
    0, 0, 0, 0, // siaddr (4 bytes)
    127, 0, 0, 1, // giaddr (4 bytes)
    0, 12, 1, 2, 3, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // chaddr (16 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, // sname (64 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, // file (128 bytes)
    99, 130, 83, 99, // magic cookie (4 bytes)
    53, 1, 1, // option 53: DHCPDISCOVER
    55, 7, 1, 28, 2, 3, 15, 6, 12, // option 55: Parameter Request List
    61, 7, 1, 0, 12, 1, 2, 3, 9,   // option 61: Client Identifier
    255, // option 255: END
];

const BASE_DHCP_PACKET: &'static [u8] = &[
    1, // op (1 byte) = BOOTREQUEST
    1, // htype (1 byte) = Ethernet
    6, // hlen (1 byte)
    1, // hops (1 byte)
    0, 0, 0, 5, // xid (4 bytes)
    0, 3, // secs (2 bytes)
    0, 0, // flags (2 bytes)
    0, 0, 0, 0, // ciaddr (4 bytes)
    0, 0, 0, 0, // yiaddr (4 bytes)
    0, 0, 0, 0, // siaddr (4 bytes)
    127, 0, 0, 1, // giaddr (4 bytes)
    0, 12, 1, 2, 3, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // chaddr (16 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, // sname (64 bytes)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, // file (128 bytes)
    99, 130, 83, 99, // magic cookie (4 bytes)
];

#[derive(Debug)]
pub struct TestPacket {
    data: Vec<u8>,
}

impl TestPacket {
    pub fn new_valid_bootp_packet() -> Self {
        Self {
            data: VALID_BOOTP_PACKET.to_vec(),
        }
    }

    pub fn new_valid_dhcp_packet() -> Self {
        Self {
            data: VALID_DHCP_PACKET.to_vec(),
        }
    }

    pub fn new_base_dhcp_packet() -> Self {
        Self {
            data: BASE_DHCP_PACKET.to_vec(),
        }
    }

    pub fn new_dhcp_packet_with_message_type(message_type: MessageType) -> Self {
        Self::new_base_dhcp_packet().append(&vec![
            OPTION_CODE_DHCP_MESSAGE_TYPE,
            1,
            message_type.into(),
        ])
    }

    pub fn get(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn set(self, pos: u32, new_data: &[u8]) -> TestPacket {
        let pos_converted = pos as usize;
        let mut data = self.data;
        data[pos_converted..pos_converted + new_data.len()].copy_from_slice(new_data);
        TestPacket { data }
    }

    pub fn append(self, new_data: &[u8]) -> TestPacket {
        let mut data = self.data;
        data.append(&mut new_data.to_vec());
        TestPacket { data }
    }
}
