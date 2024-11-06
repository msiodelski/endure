//! `buffer` is a module that provides mechanics for manipulating the data
//! in the processed packets.

use std::{
    io::{self, BufRead, Cursor, Read},
    net::Ipv4Addr,
    str::from_utf8,
    vec,
};
use thiserror::Error;

type Result<T> = std::result::Result<T, BufferError>;

/// Represents errors returned by the functions processing the buffers.
#[derive(Debug, Error, PartialEq)]
pub enum BufferError {
    /// An error returned upon an attempt to read from the buffer when the
    /// read position is out of bounds or when the buffer is too short.
    #[error("out of bounds buffer read attempt at position: {read_position:?}, read length: {read_length:?}, buffer length: {buffer_length:?}")]
    ReadOutOfBounds {
        /// The read start offset in the buffer.
        read_position: u32,
        /// The read length.
        read_length: usize,
        /// The total buffer length.
        buffer_length: usize,
    },
    /// An error returned upon an attempt to read a string from the buffer,
    /// when the string is not a valid UTF-8 string.
    #[error("error converting packet data into a utf8 string at position: {read_position:?}, read length: {read_length:?}")]
    ReadUtf8Conversion {
        /// The read start offset in the buffer.
        read_position: u32,
        /// The read length.
        read_length: usize,
    },
    #[error("unknown error while reading from the packet buffer")]
    /// An unknown IO error during the buffer read.
    Unknown,
}

/// Wraps a number ensuring it is within a desired range.
///
/// Some numbers in the parsed packets must be within certain ranges. For example,
/// the `hlen` in a `bootp` packet must be in the range of 1 to 16. If the number
/// is out of range (e.g., `hlen` greater than 16), it must be "clamped". Using an
/// out of range number would cause parsing errors and pose a risk of invalid memory
/// access. Thus, any number greater than the maximum is set to the maximum. Any number
/// lower than the minimum is set to the minimum. A number within the range is left
/// unchanged.
#[derive(Clone, Debug)]
pub struct ClampedNumber<T: PartialOrd> {
    actual: T,
    clamped: T,
}

impl<T: PartialOrd + Copy> ClampedNumber<T> {
    /// Instantiates the number with clamping.
    pub fn new(min: T, max: T, actual: T) -> ClampedNumber<T> {
        let clamped = match actual {
            actual if actual < min => min,
            actual if actual > max => max,
            _ => actual,
        };
        ClampedNumber::<T> { actual, clamped }
    }

    /// Returns the clamped number (the number in range).
    pub fn get(&self) -> T {
        self.clamped
    }

    /// Checks if the original number was out of range and had to be clamped.
    pub fn out_of_range(self) -> bool {
        self.clamped != self.actual
    }
}

/// Represents a buffer holding received data.
///
/// It provides the functions to read the formatted data from the buffer. It allows
/// for reading the data using a random access index. It means that the data can
/// be accessed selectively, without a need to parse the entire packet. Depending
/// on the packet structure, the data can be read as 1, 2 or 4 byte numbers with a
/// conversion from network to host byte order. The data can also be read as variable
/// length slices or strings.
///
/// The caller must know the positions of the desired data fields. The functions reading
/// the data seek to the specified positions. If the specified position or the read
/// data length are out of bounds the [BufferError::ReadOutOfBounds] error is returned.
#[derive(Clone, Debug)]
pub struct ReceiveBuffer {
    buffer: Vec<u8>,
}

impl ReceiveBuffer {
    /// Instantiates a buffer from a data array.
    pub fn new(data: Vec<u8>) -> ReceiveBuffer {
        ReceiveBuffer { buffer: data }
    }

    /// Attempts to read an array of bytes from the buffer.
    ///
    /// # Parameters
    ///
    /// - `N` is a number of bytes to read
    /// - `pos` is a read start position, where 0 is the first byte in the buffer
    ///
    /// # Result
    ///
    /// It returns a result with an array of bytes. If the position is out of bounds or
    /// the length spans beyond the end of the buffer it returns the [BufferError::ReadOutOfBounds]
    /// error.
    fn read<const N: usize>(&mut self, pos: u32) -> Result<[u8; N]> {
        let mut cursor = Cursor::new(&self.buffer);
        cursor.set_position(u64::from(pos));
        let mut buf: [u8; N] = [0; N];
        cursor
            .read_exact(&mut buf)
            .map(|_| buf)
            .map_err(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => BufferError::ReadOutOfBounds {
                    read_position: pos,
                    read_length: N,
                    buffer_length: self.buffer.len(),
                },
                _ => BufferError::Unknown,
            })
    }

    /// Attempts to read a vector of bytes from the buffer.
    ///
    /// This function variant reads variable length data from the buffer.
    /// If the number of bytes between the `pos` and the end of the buffer
    /// is lower than `len`, the function reads the remaining bytes until
    /// the end of the buffer. It means that the actual data length can be
    /// lower than the specified length value.
    ///
    /// # Parameters
    ///
    /// - `pos` is a read start position, where 0 is the first byte in the buffer
    /// - `len` is a number of bytes to read
    ///
    /// # Result
    ///
    /// It returns a vector of bytes that can be shorter than the desired
    /// length. If the `pos` is out of bounds, it returns the [BufferError::ReadOutOfBounds]
    /// error.
    pub fn read_vec(&mut self, pos: u32, len: usize) -> Result<Vec<u8>> {
        // We must not read from outside of the buffer.
        if pos >= self.buffer.len() as u32 {
            return Err(BufferError::ReadOutOfBounds {
                read_position: pos,
                read_length: len,
                buffer_length: self.buffer.len(),
            });
        }
        let mut len = len;
        if pos as usize + len > self.buffer.len() {
            // The buffer is not long enough. Let's read until the end of the buffer.
            len = self.buffer.len() - pos as usize;
        }
        let mut cursor = Cursor::new(&self.buffer);
        cursor.set_position(u64::from(pos));
        let mut buf: Vec<u8> = vec![0; len];
        cursor
            .read_exact(&mut buf)
            .map(|_| buf)
            .map_err(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => BufferError::ReadOutOfBounds {
                    read_position: pos,
                    read_length: len,
                    buffer_length: self.buffer.len(),
                },
                _ => BufferError::Unknown,
            })
    }

    /// Attempts to read from a buffer into a string.
    ///
    /// This function is applicable for reading the null-terminated strings from a
    /// buffer when the strings also have maximum length specified in the protocol.
    /// For example, the `sname` field in the `bootp` protocol can hold a null-terminated
    /// string that has a maximum length of 64 bytes.
    ///
    /// In practice, the strings sometimes lack the null character at the end. In these
    /// cases, the function reads all `max_len` bytes or all bytes until the end of the
    /// buffer.
    ///
    /// # Parameters
    ///
    /// - `pos` is a read start position, where 0 is the first byte in the buffer
    /// - `max_len` is a maximum number of bytes to read (if null character is not found)
    ///
    /// # Result
    ///
    /// It returns a string converted from UTF-8. If such the conversion fails it returns the
    /// [BufferError::ReadUtf8Conversion] error. If the `pos` is out of bounds, it returns
    /// the [BufferError::ReadOutOfBounds].
    pub fn read_null_terminated(&mut self, pos: u32, max_len: usize) -> Result<String> {
        // We must not read from outside of the buffer.
        if pos >= self.buffer.len() as u32 {
            return Err(BufferError::ReadOutOfBounds {
                read_position: pos,
                read_length: max_len,
                buffer_length: self.buffer.len(),
            });
        }
        let mut cursor = Cursor::new(&self.buffer);
        cursor.set_position(u64::from(pos));
        let mut buf = Vec::<u8>::new();
        // Read until we hit null (zero).
        match cursor.read_until(0, &mut buf) {
            Ok(bytes_read) => {
                if bytes_read > max_len {
                    buf.resize(max_len, 0);
                } else if *buf.last().unwrap_or(&0xff) == 0 {
                    buf.resize(buf.len() - 1, 0)
                }
                match from_utf8(&buf) {
                    Ok(s) => Ok(s.to_owned()),
                    Err(_) => Err(BufferError::ReadUtf8Conversion {
                        read_position: pos,
                        read_length: max_len,
                    }),
                }
            }
            Err(_) => Err(BufferError::Unknown),
        }
    }

    /// Attempts to read a u8 number from the buffer.
    ///
    /// # Parameters
    ///
    /// - `pos` is a read start position
    ///
    /// # Result
    ///
    /// It returns a byte read from the buffer. If the specified position is out
    /// of bounds the [BufferError::ReadOutOfBounds] is returned.
    pub fn read_u8(&mut self, pos: u32) -> Result<u8> {
        self.read::<1>(pos).map(|buf| buf[0])
    }

    /// Attempts to read a u16 number from the buffer.
    ///
    /// # Parameters
    ///
    /// - `pos` is a read start position, where 0 is the first byte in the buffer
    ///
    /// # Result
    ///
    /// It returns two bytes converted from the network to host byte order.
    /// If the specified position is out of bounds the [BufferError::ReadOutOfBounds]
    /// is returned.
    pub fn read_u16(&mut self, pos: u32) -> Result<u16> {
        self.read::<2>(pos).map(|buf| u16::from_be_bytes(buf))
    }

    /// Attempts to read a u32 number from the buffer.
    ///
    /// # Parameters
    ///
    /// - `pos` is a read start position, where 0 is the first byte in the buffer
    ///
    /// # Result
    ///
    /// It returns four bytes converted from the network to host byte order.
    /// If the specified position is out of bounds the [BufferError::ReadOutOfBounds]
    /// is returned.
    pub fn read_u32(&mut self, pos: u32) -> Result<u32> {
        self.read::<4>(pos).map(|buf| u32::from_be_bytes(buf))
    }

    /// Attempts to read an IPv4 address from the buffer.
    ///
    /// # Parameters
    ///
    /// - `pos` is a read start position, where 0 is the first byte in the buffer
    ///
    /// It reads 4 bytes and converts them to an IPv4 address. If the specified
    /// position is out of bounds the [BufferError::ReadOutOfBounds] is returned.
    pub fn read_ipv4(&mut self, pos: u32) -> Result<Ipv4Addr> {
        self.read::<4>(pos)
            .map(|buf| Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
    }
}

#[cfg(test)]
mod tests {
    use super::{ClampedNumber, ReceiveBuffer};

    #[test]
    fn clamped_number_within_range() {
        let clamped_numer = ClampedNumber::<u8>::new(5, 25, 12);
        assert_eq!(clamped_numer.get(), 12);
        assert!(!clamped_numer.out_of_range());
    }

    #[test]
    fn clamped_number_high() {
        let clamped_numer = ClampedNumber::<u8>::new(5, 20, 30);
        assert_eq!(clamped_numer.get(), 20);
        assert!(clamped_numer.out_of_range());
    }

    #[test]
    fn clamped_number_low() {
        let clamped_numer = ClampedNumber::<u8>::new(7, 20, 5);
        assert_eq!(clamped_numer.get(), 7);
        assert!(clamped_numer.out_of_range());
    }

    #[test]
    fn receive_buffer_read() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let read = buf.read::<4>(3);
        assert!(read.is_ok());
        assert_eq!(read.unwrap(), data[3..7]);

        let read = buf.read::<3>(8);
        assert!(read.is_err());
    }

    #[test]
    fn receive_buffer_read_empty_buffer() {
        let data: [u8; 0] = [];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let read = buf.read::<1>(0);
        assert!(read.is_err());
        assert_eq!(
            read.unwrap_err().to_string(),
            "out of bounds buffer read attempt at position: 0, read length: 1, buffer length: 0"
        );
    }

    #[test]
    fn receive_buffer_read_vec() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let read = buf.read_vec(3, 4);
        assert!(read.is_ok());
        assert_eq!(read.unwrap(), data[3..7]);

        let read = buf.read::<3>(8);
        assert!(read.is_err());
        assert_eq!(
            read.unwrap_err().to_string(),
            "out of bounds buffer read attempt at position: 8, read length: 3, buffer length: 10"
        )
    }

    #[test]
    fn receive_buffer_read_vec_eof() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let read = buf.read_vec(8, 10);
        assert!(read.is_ok());
        assert_eq!(read.unwrap(), data[8..10])
    }

    #[test]
    fn receive_buffer_read_vec_out_of_bounds() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let read = buf.read_vec(15, 4);
        assert!(read.is_err());
        assert_eq!(
            read.unwrap_err().to_string(),
            "out of bounds buffer read attempt at position: 15, read length: 4, buffer length: 10"
        )
    }

    #[test]
    fn receive_buffer_read_null_terminated_with_null() {
        let data: [u8; 10] = [0x65, 0x65, 0x68, 0x70, 0x71, 0x73, 0x62, 0, 0x63, 0x64];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let s = buf.read_null_terminated(1, 20);
        assert!(s.is_ok());
        assert_eq!(s.unwrap(), "ehpqsb")
    }

    #[test]
    fn receive_buffer_read_null_terminated_without_null() {
        let data: [u8; 10] = [0x65, 0x65, 0x68, 0x70, 0x71, 0x73, 0x62, 0x65, 0x63, 0x64];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let s = buf.read_null_terminated(1, 20);
        assert!(s.is_ok());
        assert_eq!(s.unwrap(), "ehpqsbecd")
    }

    #[test]
    fn receive_buffer_read_null_terminated_utf8_error() {
        // 0xc3, 0x28 is an invalid UTF-8 sequence.
        let data: [u8; 6] = [0xc3, 0x28, 0x61, 0x62, 0x63, 0];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let read = buf.read_null_terminated(0, 5);
        assert!(read.is_err());
        assert_eq!(
            read.unwrap_err().to_string(),
            "error converting packet data into a utf8 string at position: 0, read length: 5"
        )
    }

    #[test]
    fn read_u8() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let value = buf.read_u8(3);
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), 8);

        let value = buf.read_u8(10);
        assert!(value.is_err());
        assert_eq!(
            value.unwrap_err().to_string(),
            "out of bounds buffer read attempt at position: 10, read length: 1, buffer length: 10"
        );
    }

    #[test]
    fn read_u16() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let value = buf.read_u16(5);
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), 0x308);

        let value = buf.read_u16(14);
        assert!(value.is_err());
        assert_eq!(
            value.unwrap_err().to_string(),
            "out of bounds buffer read attempt at position: 14, read length: 2, buffer length: 10"
        );
    }

    #[test]
    fn read_u32() {
        let data: [u8; 10] = [5, 7, 1, 8, 9, 3, 8, 9, 10, 8];
        let mut buf = ReceiveBuffer::new(data.to_vec());

        let value = buf.read_u32(1);
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), 0x7010809);

        let value = buf.read_u32(20);
        assert!(value.is_err());
        assert_eq!(
            value.unwrap_err().to_string(),
            "out of bounds buffer read attempt at position: 20, read length: 4, buffer length: 10"
        );
    }
}
