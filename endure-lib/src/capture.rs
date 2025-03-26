//! `capture` is a module providing a function to efficiently listen on one
//! or multiple interfaces and return the received packets over the common
//! channel to a caller. It also provides the mechanism to read packets
//! from the `pcap` files.

use chrono::Local;
use futures::StreamExt;
use pcap::{Capture, Linktype, Offline, Packet, PacketCodec, PacketHeader, PacketStream, Savefile};
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::{collections::HashMap, path::Path};
use thiserror::Error;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};

/// A default length of the Ethernet frame, IP and UDP headers together.
pub const ETHERNET_IP_UDP_HEADER_LENGTH: usize = 42;

/// An offset of the source IP address in the Ethernet frame.
pub const ETHERNET_SOURCE_IP_ADDRESS_POS: usize = 26;

/// An offset of the destination IP address in the Ethernet frame.
pub const ETHERNET_DESTINATION_IP_ADDRESS_POS: usize = 30;

/// A default length of the local loopback frame, IP and UDP headers together.
pub const LOOPBACK_IP_UDP_HEADER_LENGTH: usize = 32;

/// An offset of the source IP address in the BSD loopback encapsulation.
pub const LOOPBACK_SOURCE_IP_ADDRESS_POS: usize = 26;

/// An offset of the destination IP address in the BSD loopback encapsulation.
pub const LOOPBACK_DESTINATION_IP_ADDRESS_POS: usize = 30;

/// Represents errors returned by the [`PacketWrapper::payload`].
#[derive(Debug, Error, PartialEq)]
pub enum PacketDataError {
    /// An error returned when parsing a packet with an unsupported data link type.
    #[error("unsupported data link type: {data_link:?}")]
    UnsupportedLinkType {
        /// Packet data link type.
        data_link: Linktype,
    },
    /// An error returned when parsed packet is truncated.
    #[error("truncated packet with data link type: {data_link:?}, length: {packet_length:?}, expected minimum length: {payload_offset:?}")]
    TruncatedPacket {
        /// Packet data link type.
        data_link: Linktype,
        /// Parsed packet length.
        packet_length: usize,
        /// Expected payload offset (e.g., for DHCP it is the DHCP message offset after UDP header).
        payload_offset: usize,
    },
}

/// Encapsulates a captured packet.
///
/// It holds a copy of the packet header and data received as [`pcap::Packet`].
/// We cannot use the [`pcap::Packet`] directly because it contains references
/// to the header and data, which have short lifetime. In addition, the wrapper
/// contains the filter instance, so the dispatcher can differentiate the
/// packets by the protocol and process it in a protocol-specific manner.
#[derive(Debug)]
pub struct PacketWrapper {
    /// Packet filter used to capture the packet.
    pub filter: Option<Filter>,
    /// Packet header.
    pub header: PacketHeader,
    /// Packet payload.
    pub data: Vec<u8>,
    /// Data link type.
    pub data_link: Linktype,
}

impl PacketWrapper {
    /// Returns packet payload.
    pub fn payload(&self) -> Result<&[u8], PacketDataError> {
        match self.data_link {
            Linktype::ETHERNET => {
                if self.data.len() <= ETHERNET_IP_UDP_HEADER_LENGTH {
                    return Err(PacketDataError::TruncatedPacket {
                        data_link: Linktype::ETHERNET,
                        packet_length: self.data.len(),
                        payload_offset: ETHERNET_IP_UDP_HEADER_LENGTH,
                    });
                }
                Ok(&self.data[ETHERNET_IP_UDP_HEADER_LENGTH..])
            }
            Linktype::NULL | Linktype::LOOP => {
                if self.data.len() <= LOOPBACK_IP_UDP_HEADER_LENGTH {
                    return Err(PacketDataError::TruncatedPacket {
                        data_link: Linktype::NULL,
                        packet_length: self.data.len(),
                        payload_offset: LOOPBACK_IP_UDP_HEADER_LENGTH,
                    });
                }
                Ok(&self.data[LOOPBACK_IP_UDP_HEADER_LENGTH..])
            }
            data_link => Err(PacketDataError::UnsupportedLinkType { data_link }),
        }
    }

    /// Attempts to return an IPv4 address from the packet's TCP header.
    fn ipv4_address(
        &self,
        link_type: Linktype,
        ip_address_pos: usize,
    ) -> Result<Ipv4Addr, PacketDataError> {
        if self.data.len() <= ip_address_pos {
            return Err(PacketDataError::TruncatedPacket {
                data_link: link_type,
                packet_length: self.data.len(),
                payload_offset: ip_address_pos,
            });
        }
        Ok(Ipv4Addr::new(
            self.data[ip_address_pos],
            self.data[ip_address_pos + 1],
            self.data[ip_address_pos + 2],
            self.data[ip_address_pos + 3],
        ))
    }

    /// Attempts to return an IPv4 source address from the packet's TCP header.
    ///
    /// # Errors
    ///
    /// Returns [`PacketDataError::UnsupportedLinkType`] if the data link type is not supported.
    /// Currently, only Ethernet and BSD loopback are supported. It returns [`PacketDataError::TruncatedPacket`]
    /// if the packet is truncated.
    pub fn ipv4_source_address(&self) -> Result<Ipv4Addr, PacketDataError> {
        match self.data_link {
            Linktype::ETHERNET => {
                self.ipv4_address(Linktype::ETHERNET, ETHERNET_SOURCE_IP_ADDRESS_POS)
            }
            Linktype::NULL | Linktype::LOOP => {
                self.ipv4_address(Linktype::NULL, LOOPBACK_SOURCE_IP_ADDRESS_POS)
            }
            data_link => Err(PacketDataError::UnsupportedLinkType { data_link }),
        }
    }

    /// Attempts to return an IPv4 destination address from the packet's TCP header.
    ///
    /// # Errors
    ///
    /// Returns [`PacketDataError::UnsupportedLinkType`] if the data link type is not supported.
    /// Currently, only Ethernet and BSD loopback are supported. It returns [`PacketDataError::TruncatedPacket`]
    /// if the packet is truncated.
    pub fn ipv4_destination_address(&self) -> Result<Ipv4Addr, PacketDataError> {
        match self.data_link {
            Linktype::ETHERNET => {
                self.ipv4_address(Linktype::ETHERNET, ETHERNET_DESTINATION_IP_ADDRESS_POS)
            }
            Linktype::NULL | Linktype::LOOP => {
                self.ipv4_address(Linktype::NULL, LOOPBACK_DESTINATION_IP_ADDRESS_POS)
            }
            data_link => Err(PacketDataError::UnsupportedLinkType { data_link }),
        }
    }
}

/// [`PacketWrapper`] codec.
///
/// It is used to convert packets received from the capture stream to
/// the [`PacketWrapper`] instance that can be consumed by the packet
/// analyzers.
struct PacketWrapperCodec {
    filter: Option<Filter>,
    datalink: Linktype,
    savefile: Option<Savefile>,
}

impl PacketWrapperCodec {
    fn new(datalink: Linktype) -> Self {
        Self {
            datalink,
            filter: None,
            savefile: None,
        }
    }

    /// Sets filter for a codec.
    ///
    /// If the filter is set, the codec includes it in the parsed packets.
    fn with_filter(mut self, filter: Filter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Enables pcap generation from the encoded packets.
    fn with_savefile(mut self, savefile: Savefile) -> Self {
        self.savefile = Some(savefile);
        self
    }
}

impl PacketCodec for PacketWrapperCodec {
    type Item = PacketWrapper;

    /// Wraps the received packets in the [`PacketWrapper`].
    fn decode(&mut self, packet: Packet) -> Self::Item {
        if let Some(savefile) = &mut self.savefile {
            savefile.write(&packet);
        }
        PacketWrapper {
            header: packet.header.clone(),
            data: packet.data.to_vec(),
            filter: self.filter,
            data_link: self.datalink,
        }
    }
}

/// An enum of protocols used for filtering.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Proto {
    /// Filtering by BOOTP or DHCPv4 messages.
    Bootp,
    /// Filtering by DHCPv6 messages.
    DHCPv6,
    /// Filtering by UDP messages.
    UDP,
    /// Filtering by TCP messages.
    TCP,
}

/// Represents a filter used to capture selected packets.
///
/// # Example Usage
///
/// ```rust
/// use endure_lib::capture::Filter;
///
/// Filter::new().udp().port(10067);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Filter {
    proto: Option<Proto>,
    port: Option<u16>,
}

impl Filter {
    /// Instantiates an empty packet filter.
    pub fn new() -> Self {
        Filter::default()
    }

    /// Creates a filter for capturing BOOTP packets sent to a relay or server.
    ///
    /// It sets a default port 67 used by the BOOTP servers and relays. In test
    /// labs, the servers can sometimes run on a different port. In this case,
    /// use the [`Filter::bootp`] function instead. It allows for specifying a
    /// custom port number.
    pub fn bootp_server_relay(self) -> Filter {
        self.bootp(67)
    }

    /// Creates a filter for capturing BOOTP packets at specified port.
    ///
    /// # Usage
    ///
    /// ```rust
    /// use endure_lib::capture::Filter;
    ///
    /// Filter::new().udp().port(67);
    /// ```
    ///
    /// is equivalent to:
    ///
    /// ```rust
    /// use endure_lib::capture::Filter;
    ///
    /// Filter::new().bootp_server_relay();
    /// ```
    pub fn bootp(self, port: u16) -> Filter {
        Filter {
            proto: Some(Proto::Bootp),
            port: Some(port),
            ..self
        }
    }

    /// Creates a filter for capturing DHCPv6 packets sent to a relay or server.
    ///
    /// It sets a default port 547 used by the DHCPv6 servers and relays. In test
    /// labs, the servers can sometimes run on a different port. In this case,
    /// use the [`Filter::dhcp_v6`] function instead. It allows for specifying a
    /// custom port number.
    pub fn dhcp_v6_server_relay(self) -> Filter {
        Filter {
            proto: Some(Proto::DHCPv6),
            port: Some(547),
            ..self
        }
    }

    /// Creates a filter for capturing DHCPv6 packets at specified port.
    ///
    /// # Usage
    ///
    /// ```rust
    /// use endure_lib::capture::Filter;
    ///
    /// Filter::new().udp().port(547);
    /// ```
    ///
    /// is equivalent to:
    ///
    /// ```rust
    /// use endure_lib::capture::Filter;
    ///
    /// Filter::new().dhcp_v6_server_relay();
    /// ```
    pub fn dhcp_v6(self, port: u16) -> Filter {
        Filter {
            proto: Some(Proto::DHCPv6),
            port: Some(port),
            ..self
        }
    }

    /// Creates a filter for capturing UDP packets.
    pub fn udp(self) -> Filter {
        Filter {
            proto: Some(Proto::UDP),
            ..self
        }
    }

    /// Creates a filter for capturing TCP packets.
    pub fn tcp(self) -> Filter {
        Filter {
            proto: Some(Proto::TCP),
            ..self
        }
    }

    /// Creates a filter for capturing packets at the specified port.
    pub fn port(self, port: u16) -> Filter {
        Filter {
            port: Some(port),
            ..self
        }
    }

    /// Returns protocol associated with the filter.
    pub fn get_proto(self) -> Option<Proto> {
        self.proto
    }

    /// Converts the filter to the text form.
    ///
    /// The returned value can be used directly in the [pcap] library
    /// to set the filtering program.
    pub fn to_string(&self) -> String {
        let mut filter_text: String = String::new();
        if let Some(proto) = &self.proto {
            match proto {
                Proto::TCP => filter_text.push_str("tcp"),
                _ => filter_text.push_str("udp"),
            }
        }
        if let Some(port) = &self.port {
            if !filter_text.is_empty() {
                filter_text.push_str(" ");
            }
            filter_text.push_str(format!("port {}", port).as_str())
        }
        filter_text
    }
}

/// An enum of errors returned by the [`ListenerPool::add_listener`].
#[derive(Debug, Error, PartialEq)]
pub enum ListenerAddError {
    /// Returned on an attempt to add a duplicate listener.
    ///
    /// There must be at most one listener bound to an interface.
    /// An attempt to bind another listener to the same interface
    /// yields this error. It can be returned by the
    /// [`ListenerPool::add_listener`] function.
    #[error("specified the same interface {interface_name:?} multiple names")]
    ListenerExists {
        /// An interface name.
        interface_name: String,
    },
}

/// Pool of the packet listeners.
///
/// It holds a collection of the listeners capturing traffic on
/// different interfaces. The received packets are sent over the channel
/// to the main thread for processing.
#[derive(Default)]
pub struct ListenerPool {
    listeners: HashMap<String, Listener<Inactive>>,
}

impl ListenerPool {
    /// Instantiates the [`ListenerPool`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to add a listener for a device.
    ///
    /// The listener is installed for the specific device (i.e., interface).
    /// If there is another listener installed for this device already
    /// it returns [`ListenerAddError::ListenerExists`] error.
    ///
    /// # Arguments
    ///
    /// - `listener` - instance of the listener to be added to the pool.
    pub fn add_listener(&mut self, listener: Listener<Inactive>) -> Result<(), ListenerAddError> {
        if self.listeners.contains_key(&listener.interface_name) {
            return Err(ListenerAddError::ListenerExists {
                interface_name: listener.interface_name.to_string(),
            });
        }
        self.listeners
            .insert(listener.interface_name.to_string(), listener);
        Ok(())
    }

    /// Starts all registered listeners.
    ///
    /// # Result
    ///
    /// It returns a receiver of the channel that the threads are using to
    /// notify about the received packets. Use this receiver to receive the
    /// packets captured on all interfaces.
    ///
    /// # Errors
    ///
    /// This function may return the [`pcap::Error`] when there is a problem
    /// opening any of the captures. Typically, an error is returned when the
    /// specified interface doesn't exist or the program has insufficient
    /// privileges to run the traffic capture.
    pub async fn run(self) -> Result<Receiver<PacketWrapper>, pcap::Error> {
        let (tx, rx) = tokio::sync::mpsc::channel::<PacketWrapper>(100);
        let tx = Arc::new(Mutex::new(tx));
        // Open the listeners. The listeners use the tx side of the channel to
        // send the received packets to the main thread.
        for listener in self.listeners {
            listener.1.start(Arc::clone(&tx)).await?;
        }
        Ok(rx)
    }
}

/// A trait matching all possible states for a listener.
pub trait State {}

/// Active listener state.
#[derive(Debug)]
pub enum Active {}

/// Inactive listener state.
#[derive(Debug)]
pub enum Inactive {}

impl State for Active {}
impl State for Inactive {}

/// Represents errors during capturing packets in [`Listener::start`].
///
/// These errors indicate non-recoverable conditions for the packet capture
/// from a device and terminate the capture for this device.
#[derive(Debug, Error, PartialEq)]
pub enum ListenerError {
    /// An error returned when capturing a packet from stream failed.
    #[error("attempt to receive next packet from the stream failed: {details:?}")]
    ReadStream {
        /// Error details.
        details: String,
    },

    /// An error returned when sending the received packet over the
    /// channel for processing failed.
    #[error("sending received packet over for processing failed: {details:?}")]
    SendPacket {
        /// Error details.
        details: String,
    },
}

/// Packet listener capturing packets from a single interface.
///
/// The listener is stateful. It can be in one of the two states:
/// - `Inactive` - the listener is not capturing the packets and can be configured.
/// - `Active` - the listener is capturing the packets.
///
/// There can be at most one listener instance for each interface.
#[derive(Debug)]
pub struct Listener<T: State> {
    interface_name: String,
    packet_filter: Option<Filter>,
    pcap_dir: Option<String>,
    _marker: PhantomData<T>,
}

impl Listener<Inactive> {
    /// Creates a new listener instance for the specified interface.
    ///
    /// # Arguments
    ///
    /// `interface_name` - name of the interface on which the listener should
    /// capture the packets.
    pub fn from_iface(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.to_string(),
            packet_filter: None,
            pcap_dir: None,
            _marker: PhantomData,
        }
    }

    /// Adds a capture filter to the listener.
    ///
    /// # Arguments
    ///
    /// - `packet_filter` - a packet filter instance used for capturing
    ///   a specific type of the packets.
    pub fn with_filter(mut self, packet_filter: Filter) -> Self {
        self.packet_filter = Some(packet_filter);
        self
    }

    /// Configures the listener to generate a pcap file from the stream.
    ///
    /// # Arguments
    ///
    /// - `pcap_dir` - path to a directory where pcap file should be saved.
    pub fn save_to(mut self, pcap_dir: &str) -> Self {
        self.pcap_dir = Some(pcap_dir.to_string());
        self
    }

    /// Returns a path to a pcap file generated by the listener.
    fn pcap_file(&self) -> Option<PathBuf> {
        // Optionally create a pcap file from the stream.
        if let Some(pcap_dir) = &self.pcap_dir {
            let filename = format!(
                "{}.{}.pcap",
                self.interface_name,
                Local::now().format("%Y-%m-%dT%H:%M:%S")
            );
            let path = Path::new(pcap_dir).join(filename);
            return Some(path);
        }
        None
    }

    /// Runs a loop capturing packets from a stream.
    async fn capture_packets(
        mut stream: PacketStream<pcap::Active, PacketWrapperCodec>,
        sender: Arc<Mutex<Sender<PacketWrapper>>>,
    ) -> Result<(), ListenerError> {
        while let Some(packet) = stream.next().await {
            match packet {
                Ok(packet) => sender.lock().await.send(packet).await.map_err(|err| {
                    ListenerError::SendPacket {
                        details: err.to_string(),
                    }
                })?,
                Err(err) => {
                    return Err(ListenerError::ReadStream {
                        details: err.to_string(),
                    })
                }
            }
        }
        Ok(())
    }

    /// Starts the listener.
    ///
    /// It applies the specified filter and spawns an asynchronous packet capture.
    ///
    /// # Arguments
    ///
    /// The `sender` instance is a sender side of a channel that the listener should use to
    /// provide the received packets to the caller. The caller is responsible for
    /// creating the sender and the receiver instance. It is safe to share the same
    /// sender between multiple threads. Typically, there is only one receiver instance
    /// collecting the packets from several threads.
    ///
    /// # Errors
    ///
    /// The function may return a [`pcap::Error`] when starting the capture
    /// failed. This may happen when the network device does not support
    /// `select()`.
    pub async fn start(
        self,
        sender: Arc<Mutex<Sender<PacketWrapper>>>,
    ) -> Result<Listener<Active>, pcap::Error> {
        let mut capture = Capture::from_device(self.interface_name.as_str())?
            .immediate_mode(true)
            .timeout(1000)
            .open()?
            .setnonblock()?;

        let datalink = capture.get_datalink();
        let mut codec = PacketWrapperCodec::new(datalink);

        // Optionally apply the filter.
        if let Some(filter) = self.packet_filter {
            capture.filter(filter.to_string().as_str(), false)?;
            codec = codec.with_filter(filter);
        }

        // Optionally create a pcap file from the stream.
        if let Some(pcap_file) = self.pcap_file() {
            codec = codec.with_savefile(capture.savefile(pcap_file)?);
        }

        let stream = capture.stream(codec)?;

        // Spawn the asynchronous capture.
        let _ = tokio::spawn(Self::capture_packets(stream, sender));
        Ok(Listener::<Active> {
            interface_name: self.interface_name,
            packet_filter: self.packet_filter,
            pcap_dir: self.pcap_dir,
            _marker: PhantomData,
        })
    }

    /// Finds a loopback interface name.
    ///
    /// # Result
    ///
    /// It returns the loopback interface name (typically `lo`). It may return
    /// `None` if the loopback interface doesn't exist.
    pub fn loopback_name() -> Option<String> {
        let device_list = pcap::Device::list();
        match device_list {
            Ok(device_list) => {
                return device_list
                    .iter()
                    .find(|device| device.flags.is_loopback())
                    .map(|device| device.name.clone())
            }
            Err(_) => return None,
        }
    }
}

impl Listener<Active> {}

/// Represents errors during reading packets in [`Reader::<Active>::read_next`].
///
/// These errors indicate non-recoverable conditions for the packet capture
/// from a device and terminate the capture for this device.
#[derive(Debug, Error, PartialEq)]
pub enum ReaderError {
    /// An error returned when starting the reader failed.
    #[error("reading pcap file: {pcap:?} failed: {details:?}")]
    Start {
        /// `pcap` file location.
        pcap: String,
        /// Error details.
        details: String,
    },
    /// An error returned when setting a capture filter for a `pcap` file failed.
    #[error("setting filter on pcap file: {pcap:?} failed: {details:?}")]
    Filter {
        /// `pcap` file location.
        pcap: String,
        /// Error details.
        details: String,
    },
    /// An error returned when reading next packet failed.
    #[error("attempt to read next packet from the file failed: {details:?}")]
    ReadNext {
        /// Error details.
        details: String,
    },
    #[error("end of the capture file")]
    /// An error returned when the capture file ends.
    Eof {},
}

/// Packet reader from `pcap` files.
///
/// The [`Reader`] is stateful. It can be in one of the two states:
/// - `Inactive` - the reader can be configured and is not reading a file.
/// - `Active` - the reader is reading the packets from the `pcap` file.
///
pub struct Reader<T: State> {
    pcap_path: String,
    packet_filter: Option<Filter>,
    capture: Option<Capture<Offline>>,
    _marker: PhantomData<T>,
}

impl Reader<Inactive> {
    /// Creates a new reader instance for a specified file.
    ///
    /// # Arguments
    ///
    /// `pcap_name` - name of the `pcap` file to read.
    ///
    pub fn from_pcap(pcap_name: &str) -> Self {
        Self {
            pcap_path: pcap_name.to_string(),
            packet_filter: None,
            capture: None,
            _marker: PhantomData,
        }
    }

    /// Adds a capture filter to the reader.
    ///
    /// # Arguments
    ///
    /// - `packet_filter` - a packet filter instance used for capturing
    ///   a specific type of the packets.
    ///
    pub fn with_filter(mut self, packet_filter: Filter) -> Self {
        self.packet_filter = Some(packet_filter);
        self
    }

    /// Starts the reader by turning it to [`Reader<Active>`].
    pub fn start(&self) -> Result<Reader<Active>, ReaderError> {
        let mut capture =
            Capture::from_file(self.pcap_path.clone()).map_err(|err| ReaderError::Start {
                pcap: self.pcap_path.clone(),
                details: err.to_string(),
            })?;

        if let Some(filter) = self.packet_filter {
            capture
                .filter(filter.to_string().as_str(), false)
                .map_err(|err| ReaderError::Filter {
                    pcap: self.pcap_path.clone(),
                    details: err.to_string(),
                })?;
        }

        Ok(Reader::<Active> {
            pcap_path: self.pcap_path.clone(),
            packet_filter: self.packet_filter,
            capture: Some(capture),
            _marker: PhantomData,
        })
    }
}

impl Reader<Active> {
    /// Reads next available packet from the file.
    ///
    /// # Result
    ///
    /// This function may return a [`ReaderError`] when reading the packet from
    /// the `pcap` file fails. Otherwise, it returns a [`PacketWrapper`] instance
    /// holding the packet data.
    ///
    pub fn read_next(&mut self) -> Result<PacketWrapper, ReaderError> {
        let capture = self.capture.as_mut().unwrap();
        let packet = capture.next_packet().map_err(|err| match err {
            pcap::Error::NoMorePackets => ReaderError::Eof {},
            _ => ReaderError::ReadNext {
                details: err.to_string(),
            },
        })?;
        Ok(PacketWrapper {
            header: packet.header.clone(),
            data: packet.data.to_vec(),
            filter: self.packet_filter,
            data_link: capture.get_datalink(),
        })
    }
}

impl<T> Reader<T>
where
    T: State,
{
    /// Returns `pcap` file path.
    pub fn pcap_path(&self) -> String {
        self.pcap_path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketWrapper, PacketWrapperCodec, Reader};
    use crate::capture::{
        Filter, Listener, ListenerAddError, ListenerPool, PacketDataError, Proto, ReaderError,
        ETHERNET_DESTINATION_IP_ADDRESS_POS, ETHERNET_SOURCE_IP_ADDRESS_POS,
        LOOPBACK_DESTINATION_IP_ADDRESS_POS, LOOPBACK_SOURCE_IP_ADDRESS_POS,
    };
    use pcap::{Device, Linktype, Packet, PacketCodec, PacketHeader};
    use predicates::prelude::*;
    #[cfg(test)]
    use pretty_assertions::assert_eq;
    use rstest::{fixture, rstest};
    use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};
    use tokio::sync::Mutex;

    #[test]
    fn filter_new() {
        let filter = Filter::new();
        assert_eq!(filter.proto, None);
        assert_eq!(filter.port, None);
        assert_eq!(filter.to_string(), "")
    }

    #[test]
    fn filter_dhcp_v4_server_relay() {
        let filter = Filter::new().bootp_server_relay();
        assert_eq!(filter.proto, Some(Proto::Bootp));
        assert_eq!(filter.port, Some(67));
        assert_eq!(filter.to_string(), "udp port 67");
    }

    #[test]
    fn filter_dhcp_v4() {
        let filter = Filter::new().bootp(167);
        assert_eq!(filter.proto, Some(Proto::Bootp));
        assert_eq!(filter.port, Some(167));
        assert_eq!(filter.to_string(), "udp port 167");
    }

    #[test]
    fn filter_dhcp_v6_server_relay() {
        let filter = Filter::new().dhcp_v6_server_relay();
        assert_eq!(filter.proto, Some(Proto::DHCPv6));
        assert_eq!(filter.port, Some(547));
        assert_eq!(filter.to_string(), "udp port 547");
    }

    #[test]
    fn filter_dhcp_v6() {
        let filter = Filter::new().dhcp_v6(1547);
        assert_eq!(filter.proto, Some(Proto::DHCPv6));
        assert_eq!(filter.port, Some(1547));
        assert_eq!(filter.to_string(), "udp port 1547");
    }

    #[test]
    fn filter_udp() {
        let filter = Filter::new().udp();
        assert_eq!(filter.proto, Some(Proto::UDP));
        assert_eq!(filter.port, None);
        assert_eq!(filter.to_string(), "udp");
    }

    #[test]
    fn filter_tcp() {
        let filter = Filter::new().tcp();
        assert_eq!(filter.proto, Some(Proto::TCP));
        assert_eq!(filter.port, None);
        assert_eq!(filter.to_string(), "tcp");
    }

    #[test]
    fn packet_payload_eth() {
        let packet_wrapper = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::ETHERNET,
        };
        let payload = packet_wrapper.payload();
        assert!(payload.is_ok());
        let payload = payload.unwrap();
        assert_eq!(58, payload.len());
    }

    #[test]
    fn packet_payload_eth_truncated() {
        let packet_wrapper = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 42],
            data_link: Linktype::ETHERNET,
        };
        let payload = packet_wrapper.payload();
        assert!(matches!(
            payload.unwrap_err(),
            PacketDataError::TruncatedPacket { .. }
        ));
    }

    #[test]
    fn packet_payload_null() {
        let packet_wrapper = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::NULL,
        };
        let payload = packet_wrapper.payload();
        assert!(payload.is_ok());
        let payload = payload.unwrap();
        assert_eq!(68, payload.len());
    }

    #[test]
    fn packet_payload_null_truncated() {
        let packet_wrapper = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 10],
            data_link: Linktype::NULL,
        };
        let payload = packet_wrapper.payload();
        assert!(matches!(
            payload.unwrap_err(),
            PacketDataError::TruncatedPacket { .. }
        ));
    }

    #[test]
    fn packet_payload_loop() {
        let packet_wrapper = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::LOOP,
        };
        let payload = packet_wrapper.payload();
        assert!(payload.is_ok());
        let payload = payload.unwrap();
        assert_eq!(68, payload.len());
    }

    #[test]
    fn packet_payload_loop_truncated() {
        let packet_wrapper = PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 10],
            data_link: Linktype::LOOP,
        };
        let payload = packet_wrapper.payload();
        assert!(matches!(
            payload.unwrap_err(),
            PacketDataError::TruncatedPacket { .. }
        ));
    }

    #[fixture]
    fn packet_wrapper(
        #[default(Linktype::ETHERNET)] data_link: Linktype,
        #[default(100)] data_length: usize,
    ) -> PacketWrapper {
        PacketWrapper {
            filter: None,
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; data_length],
            data_link: data_link,
        }
    }

    #[rstest]
    #[case(Linktype::ETHERNET, ETHERNET_SOURCE_IP_ADDRESS_POS)]
    #[case(Linktype::NULL, LOOPBACK_SOURCE_IP_ADDRESS_POS)]
    #[case(Linktype::LOOP, LOOPBACK_SOURCE_IP_ADDRESS_POS)]
    fn packet_ipv4_source_address(
        #[case] data_link: Linktype,
        #[case] ip_address_pos: usize,
        mut packet_wrapper: PacketWrapper,
    ) {
        packet_wrapper.data_link = data_link;
        packet_wrapper.data[ip_address_pos..ip_address_pos + 4].copy_from_slice(&[127, 1, 2, 1]);
        let source_address = packet_wrapper.ipv4_source_address();
        assert!(source_address.is_ok());
        assert_eq!(Ipv4Addr::new(127, 1, 2, 1), source_address.unwrap());
    }

    #[rstest]
    fn packet_ipv4_source_address_unsupported_link_type(
        #[with(Linktype::ATM_RFC1483)] packet_wrapper: PacketWrapper,
    ) {
        let source_address = packet_wrapper.ipv4_source_address();
        assert!(matches!(
            source_address,
            Err(PacketDataError::UnsupportedLinkType { .. })
        ));
    }

    #[rstest]
    fn packet_ipv4_source_address_truncated(
        #[with(Linktype::ETHERNET, 10)] packet_wrapper: PacketWrapper,
    ) {
        let source_address = packet_wrapper.ipv4_source_address();
        assert!(matches!(
            source_address,
            Err(PacketDataError::TruncatedPacket { .. })
        ));
    }

    #[rstest]
    #[case(Linktype::ETHERNET, ETHERNET_DESTINATION_IP_ADDRESS_POS)]
    #[case(Linktype::NULL, LOOPBACK_DESTINATION_IP_ADDRESS_POS)]
    #[case(Linktype::LOOP, LOOPBACK_DESTINATION_IP_ADDRESS_POS)]
    fn packet_ipv4_destination_address(
        #[case] data_link: Linktype,
        #[case] ip_address_pos: usize,
        mut packet_wrapper: PacketWrapper,
    ) {
        packet_wrapper.data_link = data_link;
        packet_wrapper.data[ip_address_pos..ip_address_pos + 4].copy_from_slice(&[127, 1, 2, 1]);
        let destination_address = packet_wrapper.ipv4_destination_address();
        assert!(destination_address.is_ok());
        assert_eq!(Ipv4Addr::new(127, 1, 2, 1), destination_address.unwrap());
    }

    #[rstest]
    fn packet_ipv4_destination_address_unsupported_link_type(
        #[with(Linktype::ATM_RFC1483)] packet_wrapper: PacketWrapper,
    ) {
        let destination_address = packet_wrapper.ipv4_destination_address();
        assert!(matches!(
            destination_address,
            Err(PacketDataError::UnsupportedLinkType { .. })
        ));
    }

    #[rstest]
    fn packet_ipv4_destination_address_truncated(
        #[with(Linktype::ETHERNET, 10)] packet_wrapper: PacketWrapper,
    ) {
        let destination_address = packet_wrapper.ipv4_destination_address();
        assert!(matches!(
            destination_address,
            Err(PacketDataError::TruncatedPacket { .. })
        ));
    }

    #[test]
    fn packet_wrapper_codec() {
        let data = vec![0; 10];
        let packet = Packet {
            header: &PacketHeader {
                ts: libc::timeval {
                    tv_sec: 1,
                    tv_usec: 2,
                },
                caplen: 10,
                len: 11,
            },
            data: data.as_ref(),
        };
        let mut codec =
            PacketWrapperCodec::new(Linktype::ATM_RFC1483).with_filter(Filter::new().bootp(67));
        let packet_wrapper = codec.decode(packet);
        assert!(packet_wrapper.filter.is_some());
        assert_eq!("udp port 67", packet_wrapper.filter.unwrap().to_string());
        assert_eq!(Linktype::ATM_RFC1483, packet_wrapper.data_link);
        assert_eq!(10, packet_wrapper.header.caplen);
        assert_eq!(11, packet_wrapper.header.len);
        assert_eq!(1, packet_wrapper.header.ts.tv_sec);
        assert_eq!(2, packet_wrapper.header.ts.tv_usec);
        assert_eq!(data, packet_wrapper.data);
    }

    #[test]
    fn add_listener() {
        let mut listener_pool = ListenerPool::new();
        let filter = Filter::new().udp();
        let listener = Listener::from_iface("lo").with_filter(filter);
        assert!(listener_pool.add_listener(listener).is_ok());
        assert!(matches!(
            listener_pool
                .add_listener(Listener::from_iface("lo"))
                .unwrap_err(),
            ListenerAddError::ListenerExists { .. }
        ));
        assert!(listener_pool
            .add_listener(Listener::from_iface("lo0"))
            .is_ok());
    }

    #[tokio::test]
    async fn start_listener_wrong_iface_name() {
        let listener = Listener::from_iface("non_existing_interface");
        let (tx, _) = tokio::sync::mpsc::channel::<PacketWrapper>(100);
        let tx = Arc::new(Mutex::new(tx));
        let result = listener.start(tx).await;
        assert!(result.is_err());
        assert_eq!(
            "libpcap error: No such device exists",
            result.unwrap_err().to_string()
        )
    }

    #[test]
    fn pcap_filename() {
        let listener = Listener::from_iface("enp0s3").save_to("/tmp/");
        let pcap_file = listener.pcap_file();
        assert!(pcap_file.is_some());
        let pred = predicate::str::is_match(
            "/tmp/enp0s3.\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.pcap",
        )
        .unwrap();
        assert!(pred.eval(
            pcap_file
                .unwrap()
                .as_os_str()
                .to_os_string()
                .to_str()
                .unwrap()
        ));
    }

    #[test]
    fn pcap_filename_unspecified() {
        let listener = Listener::from_iface("enp0s3");
        let pcap_file = listener.pcap_file();
        assert!(pcap_file.is_none());
    }

    #[test]
    fn pcap_filename_not_directory() {
        let listener = Listener::from_iface("enp0s3").save_to("/tmp/foo.txt");
        let pcap_file = listener.pcap_file();
        assert!(pcap_file.is_some());
    }

    #[test]
    #[ignore]
    fn loopback_name() {
        let loopback = Listener::loopback_name();
        assert!(loopback.is_some());
        let loopback = loopback.unwrap();

        // List all devices and find the loopback.
        let device_list = Device::list();
        assert!(device_list.is_ok());

        // Find the matching interface.
        let device_list = device_list.unwrap();
        let listed_loopback = device_list.iter().find(|device| device.name == loopback);
        assert!(listed_loopback.is_some());

        // Make sure it is loopback.
        let listed_loopback = listed_loopback.unwrap();
        assert!(listed_loopback.flags.is_loopback())
    }

    #[test]
    fn reader_process_capture() {
        let mut pcap_name = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pcap_name.push("../tests/resources/pcap/capture000.pcap");
        let reader = Reader::from_pcap(pcap_name.as_os_str().to_str().unwrap());
        let reader = reader.start();
        assert!(reader.is_ok());
        let mut reader = reader.unwrap();
        let mut result = reader.read_next();
        assert!(result.is_ok());
        loop {
            result = reader.read_next();
            if result.is_err() {
                assert!(matches!(result, Err(ReaderError::Eof { .. })));
                return;
            }
        }
    }

    #[test]
    fn reader_no_such_file() {
        let mut pcap_name = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pcap_name.push("../tests/resources/pcap/non-existing.pcap");
        let reader = Reader::from_pcap(pcap_name.as_os_str().to_str().unwrap());
        let result = reader.start();
        assert!(result.is_err());
        assert!(matches!(result, Err(ReaderError::Start { .. })))
    }

    #[test]
    fn reader_pcap_path() {
        let mut pcap_name = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pcap_name.push("../tests/resources/pcap/capture000.pcap");
        let reader = Reader::from_pcap(pcap_name.as_os_str().to_str().unwrap());
        let path = reader.pcap_path();
        assert_eq!(pcap_name.as_os_str().to_str().unwrap(), path)
    }
}
