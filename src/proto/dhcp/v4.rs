use std::{collections::HashMap};

use crate::proto::{dhcp, bootp};

struct Raw;

struct PartiallyParsed<'a> {
    options: HashMap<u8, ReceivedOption<'a>>
}

pub struct ReceivedPacket<'a, State> {
    data: &'a[u8],
    state: State
}

#[derive(Clone, Copy)]
pub struct ReceivedOption<'a> {
    code: u8,
    data: &'a[u8]
}

impl <'a> PartiallyParsed<'a> {
    fn option_or_insert(&mut self, option: ReceivedOption<'a>) -> &mut ReceivedOption<'a> {
        let option = self.options.entry(option.code).or_insert(option);
        option
    }

    fn option_mut(&mut self, code: u8) -> Option<&mut ReceivedOption<'a>> {
        self.options.get_mut(&code)
    }
}

impl <'a> ReceivedPacket<'a, Raw> {
    fn new(data: &'a [u8]) -> ReceivedPacket<'a, Raw> {
        ReceivedPacket {
            data,
            state: Raw,
        }
    }

    fn as_bootp(self) -> bootp::ReceivedPacket<'a, bootp::RawState> {
        bootp::ReceivedPacket::new(self.data)
    }
    fn into_parsable(self) -> ReceivedPacket<'a, PartiallyParsed<'a>> {
        ReceivedPacket::<'a, PartiallyParsed> {
            data: self.data,
            state: PartiallyParsed::<'a>{
                options: HashMap::new()
            },
        }
    }
}

impl <'a> ReceivedPacket<'a, PartiallyParsed<'a>> {
    fn option(&mut self, code: u8) -> &mut ReceivedOption<'a> {
        self.state.option_or_insert(ReceivedOption {
            code: self.data[0],
            data: &self.data[1..]
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::dhcp::{v4::ReceivedPacket};

    #[test]
    fn dhcp_packet() {
        let buffer: [u8; 3] = [0, 1, 2];

        let packet = ReceivedPacket::new(&buffer);

        assert!(packet.data[0] == 0);

        let mut v4 = packet.into_parsable();
        let option56 = v4.option(56);
        let option54 = v4.option(54);
    }
}