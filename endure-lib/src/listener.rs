//! `listener` is a module providing a function to efficiently listen on one
//! or multiple interfaces and return the received packets over the callbacks
//! mechanism to a caller.

use async_trait::async_trait;
use futures::executor::block_on;
use pcap::{Capture, Linktype, PacketHeader};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, Sender};

/// A default length of the Ethernet frame, IP and UDP headers together.
pub const ETHERNET_IP_UDP_HEADER_LENGTH: usize = 42;

/// A default length of the local loopback frame, IP and UDP headers together.
pub const LOOPBACK_IP_UDP_HEADER_LENGTH: usize = 32;

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

/// Encapsulates the captured packet.
///
/// It holds a copy of the packet header and data received as [`pcap::Packet`].
/// We cannot use the [pcap::Packet] directly because it contains references
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
/// It holds a collection of the listeners capturing a traffic on
/// different interfaces. The received packets are sent over the channel
/// to the main thread for processing.
#[derive(Default)]
pub struct ListenerPool {
    listeners: HashMap<String, Listener>,
}

impl ListenerPool {
    /// Instantiates the [`ListenerPool`].
    pub fn new() -> Self {
        ListenerPool::default()
    }

    /// Attempts to add a listener for a device.
    ///
    /// The listener is installed for the specific device (i.e., interface).
    /// If there is another listener installed for this device already
    /// it returns [`ListenerAddError::ListenerExists`] error.
    ///
    /// The [Filter] applies filtering rules for packets capturing. For example,
    /// it can be used to filter only BOOTP packets, only UDP packets, select
    /// port number etc.
    pub fn add_listener(
        &mut self,
        interface_name: &str,
        filter: &Filter,
    ) -> Result<(), ListenerAddError> {
        if self.listeners.contains_key(interface_name) {
            return Err(ListenerAddError::ListenerExists {
                interface_name: interface_name.to_string(),
            });
        }
        let mut listener = Listener::new(interface_name);
        listener.filter(filter);
        self.listeners.insert(interface_name.to_string(), listener);
        Ok(())
    }

    /// Starts all registered listeners.
    ///
    /// It spawns a new thread for each listener.
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
    pub async fn run(&mut self) -> Result<Receiver<PacketWrapper>, pcap::Error> {
        let (tx, rx) = tokio::sync::mpsc::channel::<PacketWrapper>(100);
        let tx = Arc::new(Mutex::new(tx));
        // Open the listeners. The listeners use the tx side of the channel to
        // send the received packets to the main thread.
        for listener in &mut self.listeners {
            listener.1.start(Arc::clone(&tx)).await?;
        }
        Ok(rx)
    }
}

/// A trait for a listener's state.
///
/// A listener can be in [Inactive] or [Active] state.
#[async_trait]
trait State {
    /// Applies the filter to be used for capturing the packets.
    ///
    /// # Arguments
    ///
    /// - `packet_filter` - a packet filter instance used for capturing
    ///   a specific type of the packets.
    ///
    /// # Usage Note
    ///
    /// A filter is only applied when the listener is in the [Inactive]
    /// state.
    fn filter(self: Box<Self>, packet_filter: &Filter) -> Box<dyn State>;

    /// Starts the listener thread if not started yet.
    ///
    /// # Arguments
    ///
    /// - `sender` - sender side of the channel to provide the captured
    ///   packets to the main thread.
    ///
    /// # Usage Note
    ///
    /// When the listener has already been started calling this function
    /// has no effect.
    ///
    /// # Errors
    ///
    /// The function may return a [`pcap::Error`] when starting the capture
    /// failed.
    async fn start(
        self: Box<Self>,
        sender: Arc<Mutex<Sender<PacketWrapper>>>,
    ) -> Result<Box<dyn State>, pcap::Error>;
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
/// use endure_lib::listener::Filter;
///
/// Filter::new().udp().port(10067);
/// ```
#[derive(Copy, Debug)]
pub struct Filter {
    proto: Option<Proto>,
    port: Option<u16>,
}

impl Filter {
    /// Instantiates an empty packet filter.
    pub fn new() -> Filter {
        Filter {
            proto: None,
            port: None,
        }
    }

    /// Creates a filter for capturing BOOTP packets sent to a relay or server.
    ///
    /// It sets a default port 67 used by the BOOTP servers and relays. In test
    /// labs, the servers can sometimes run on a different port. In this case,
    /// use the [Filter::bootp] function instead. It allows for specifying a
    /// custom port number.
    pub fn bootp_server_relay(self) -> Filter {
        self.bootp(67)
    }

    /// Creates a filter for capturing BOOTP packets at specified port.
    ///
    /// # Usage
    ///
    /// ```rust
    /// use endure_lib::listener::Filter;
    ///
    /// Filter::new().udp().port(67);
    /// ```
    ///
    /// is equivalent to:
    ///
    /// ```rust
    /// use endure_lib::listener::Filter;
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
    /// use the [Filter::dhcp_v6] function instead. It allows for specifying a
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
    /// use endure_lib::listener::Filter;
    ///
    /// Filter::new().udp().port(547);
    /// ```
    ///
    /// is equivalent to:
    ///
    /// ```rust
    /// use endure_lib::listener::Filter;
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
    pub fn to_text(&self) -> String {
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

impl Clone for Filter {
    fn clone(&self) -> Filter {
        Filter {
            proto: self.proto.clone(),
            port: self.port.clone(),
        }
    }
}

/// Packet listener capturing packets from a single interface.
///
/// The listener is stateful. It can be in one of the two states:
/// - Inactive - the listener is not capturing the packets and can be configured.
/// - Active - the listener is capturing the packets.
///
/// There can be at most one listener instance for each interface.
///
/// # Issues with Stopping the Listener
///
/// A started listener can't be stopped. Its thread performs the blocking
/// calls to receive packets. In the initial program version, we tried to
/// set a timeout on the capture to break the blocking calls, but didn't work
/// on the Linux systems using `TPACKET_V3`. See
/// <https://www.tcpdump.org/faq.html#q15> for details.
pub struct Listener {
    state: Option<Box<dyn State>>,
}

impl Listener {
    /// Creates a new listener instance for the specified interface.
    ///
    /// # Arguments
    ///
    /// `interface_name` - name of the interface on which the listener should
    /// capture the packets.
    pub fn new(interface_name: &str) -> Listener {
        Listener {
            state: Some(Box::new(Inactive {
                interface_name: interface_name.to_string(),
                filter: None,
            })),
        }
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

    /// Adds a capture filter for the listener.
    ///
    /// # Arguments
    ///
    /// - `packet_filter` - a packet filter instance used for capturing
    ///   a specific type of the packets.
    pub fn filter(&mut self, packet_filter: &Filter) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.filter(packet_filter))
        }
    }

    /// Starts the listener.
    ///
    /// It applies the specified filter and spawns a new thread to capture packets.
    /// It changes the listener's state to Active.
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
    /// failed.
    pub async fn start(
        &mut self,
        sender: Arc<Mutex<Sender<PacketWrapper>>>,
    ) -> Result<(), pcap::Error> {
        if let Some(s) = self.state.take() {
            self.state = Some(s.start(sender).await?)
        }
        Ok(())
    }
}

/// Represents a state of the [Listener] before it is run.
struct Inactive {
    /// Name of the interface from which the packets are captured.
    interface_name: String,
    /// A filter to be used in packets capturing.
    filter: Option<Filter>,
}

#[async_trait]
impl State for Inactive {
    fn filter(self: Box<Self>, packet_filter: &Filter) -> Box<dyn State> {
        Box::new(Inactive {
            interface_name: self.interface_name.to_string(),
            filter: Some(packet_filter.clone()),
        })
    }

    async fn start(
        self: Box<Self>,
        sender: Arc<Mutex<Sender<PacketWrapper>>>,
    ) -> Result<Box<dyn State>, pcap::Error> {
        let mut capture = Capture::from_device(self.interface_name.as_str())
            .expect("failed to open capture")
            .timeout(1000)
            .open()?;

        if let Some(filter) = &self.filter {
            capture
                .filter(filter.to_text().as_str(), false)
                .expect("failed to set filter program");
        }

        let filter = self.filter.clone();
        let _ = tokio::task::spawn_blocking(move || loop {
            if let Ok(packet) = capture.next_packet() {
                let packet = PacketWrapper {
                    header: packet.header.clone(),
                    data: packet.data.to_vec(),
                    filter: filter.clone(),
                    data_link: capture.get_datalink(),
                };
                let locked_sender = sender.lock();
                match locked_sender {
                    Ok(locked_sender) => {
                        let send_result = block_on(locked_sender.send(packet));
                        // An error sending the packet indicates that the channel has been closed
                        // or the receiver is no longer listening. The thread should return because
                        // there is no way to recover.
                        if send_result.is_err() {
                            return;
                        }
                    }
                    // If we were unable to lock the sender the channel must have been closed.
                    // We're unable to recover from this situation.
                    Err(_) => return,
                }
            }
        });
        Ok(Box::new(Active {}))
    }
}

/// Represents a state of the running [Listener].
struct Active {}

#[async_trait]
impl State for Active {
    fn filter(self: Box<Self>, _packet_filter: &Filter) -> Box<dyn State> {
        self
    }

    async fn start(
        self: Box<Self>,
        _sender: Arc<Mutex<Sender<PacketWrapper>>>,
    ) -> Result<Box<dyn State>, pcap::Error> {
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use pcap::{Linktype, PacketHeader};

    use crate::listener::{Filter, ListenerAddError, ListenerPool, PacketDataError, Proto};

    use super::PacketWrapper;

    #[test]
    fn filter_new() {
        let filter = Filter::new();
        assert_eq!(filter.proto, None);
        assert_eq!(filter.port, None);
        assert_eq!(filter.to_text(), "")
    }

    #[test]
    fn filter_dhcp_v4_server_relay() {
        let filter = Filter::new().bootp_server_relay();
        assert_eq!(filter.proto, Some(Proto::Bootp));
        assert_eq!(filter.port, Some(67));
        assert_eq!(filter.to_text(), "udp port 67");
    }

    #[test]
    fn filter_dhcp_v4() {
        let filter = Filter::new().bootp(167);
        assert_eq!(filter.proto, Some(Proto::Bootp));
        assert_eq!(filter.port, Some(167));
        assert_eq!(filter.to_text(), "udp port 167");
    }

    #[test]
    fn filter_dhcp_v6_server_relay() {
        let filter = Filter::new().dhcp_v6_server_relay();
        assert_eq!(filter.proto, Some(Proto::DHCPv6));
        assert_eq!(filter.port, Some(547));
        assert_eq!(filter.to_text(), "udp port 547");
    }

    #[test]
    fn filter_dhcp_v6() {
        let filter = Filter::new().dhcp_v6(1547);
        assert_eq!(filter.proto, Some(Proto::DHCPv6));
        assert_eq!(filter.port, Some(1547));
        assert_eq!(filter.to_text(), "udp port 1547");
    }

    #[test]
    fn filter_udp() {
        let filter = Filter::new().udp();
        assert_eq!(filter.proto, Some(Proto::UDP));
        assert_eq!(filter.port, None);
        assert_eq!(filter.to_text(), "udp");
    }

    #[test]
    fn filter_tcp() {
        let filter = Filter::new().tcp();
        assert_eq!(filter.proto, Some(Proto::TCP));
        assert_eq!(filter.port, None);
        assert_eq!(filter.to_text(), "tcp");
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

    #[test]
    fn add_listener() {
        let mut listener_pool = ListenerPool::new();
        let filter = Filter::new().udp();
        assert_eq!(listener_pool.add_listener("lo", &filter), Ok(()));
        assert!(matches!(
            listener_pool.add_listener("lo", &Filter::new()).unwrap_err(),
            ListenerAddError::ListenerExists { .. }
        ));
        assert_eq!(listener_pool.add_listener("lo0", &Filter::new()), Ok(()));
    }

}