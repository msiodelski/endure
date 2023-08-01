const VALID_BOOTP_PACKET: &'static [u8] = &[
    2,                            // op (1 byte) = BOOTREPLY
    1,                            // htype (1 byte) = Ethernet
    6,                            // hlen (1 byte)
    1,                            // hops (1 byte)
    67, 85, 120, 131,             // xid (4 bytes)
    0, 1,                         // secs (2 bytes) = 1 s
    128, 0,                       // reserved (2 bytes)
    192, 0, 2, 22,                // ciaddr (4 bytes)
    192, 0, 2, 23,                // yiaddr (4 bytes)
    10, 15, 23, 12,               // siaddr (4 bytes)
    192, 0, 2, 1,                 // giaddr (4 bytes)
    45, 32, 89, 43, 12, 22, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,       // chaddr (16 bytes)
    102, 111, 111, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,       // sname (64 bytes)
    47, 116, 109, 112, 47, 98, 111, 111,
    116, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,       // file (128 bytes) = /tmp/boot
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,       // vend (64 bytes)
];

pub struct TestBootpPacket {
    data: Vec<u8>
}

impl TestBootpPacket {
    pub fn new() -> TestBootpPacket {
        TestBootpPacket{
            data: VALID_BOOTP_PACKET.to_vec(),
        }
    }

    pub fn get(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn set(self, pos: u32, new_data: &[u8]) -> TestBootpPacket {
        let pos_converted = pos as usize;
        let mut data = self.data;
        data[pos_converted..pos_converted+new_data.len()].copy_from_slice(new_data);
        TestBootpPacket { data }
    }
}