//! `listener` is a module providing a function to efficiently listen on one
//! or multiple interfaces and return the received packets over the callbacks
//! mechanism to a caller.

use pcap::{Capture, PacketHeader};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::thread::Event;

/// Encapsulates the captured packet.
///
/// It holds a copy of the packet header and data received as [pcap::Packet].
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
}

/// Packet listener capturing packets from a single interface.
///
/// The listener is stateful. It can be in one of the two states:
/// - [Inactive] - the listener is not capturing the packets and can be configured.
/// - [Active] - the listener is capturing the packets.
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

/// A trait for a listener's state.
///
/// A listener can be in [Inactive] or [Active] state.
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
    fn filter(self: Box<Self>, packet_filter: Filter) -> Box<dyn State>;

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
    fn start(self: Box<Self>, sender: Arc<Mutex<Sender<Event>>>) -> Box<dyn State>;
}

/// Represents a state of the [Listener] before it is run.
struct Inactive {
    /// Name of the interface from which the packets are captured.
    interface_name: String,
    /// A filter to be used in packets capturing.
    filter: Option<Filter>,
}

/// Represents a state of the running [Listener].
struct Active {}

/// An enum of protocols used for filtering.
#[derive(Clone, Debug, PartialEq)]
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
/// let filter = Filter::new().udp().port(10067);
/// ```
#[derive(Debug)]
pub struct Filter {
    proto: Option<Proto>,
    port: Option<u16>,
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

    /// Adds a capture filter for the listener.
    ///
    /// # Arguments
    ///
    /// - `packet_filter` - a packet filter instance used for capturing
    ///   a specific type of the packets.
    pub fn filter(&mut self, packet_filter: Filter) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.filter(packet_filter))
        }
    }

    /// Starts the listener.
    ///
    /// It applies the specified filter and spawns a new thread to capture packets.
    /// It changes the listener's state to [Active].
    ///
    /// # Arguments
    ///
    /// The `sender` instance is a sender side of a channel that the listener should use to
    /// provide the received packets to the caller. The caller is responsible for
    /// creating the sender and the receiver instance. It is safe to share the same
    /// sender between multiple threads. Typically, there is only one receiver instance
    /// collecting the packets from several threads.
    pub fn start(&mut self, sender: Arc<Mutex<Sender<Event>>>) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.start(sender))
        }
    }
}

impl State for Inactive {
    fn filter(self: Box<Self>, packet_filter: Filter) -> Box<dyn State> {
        Box::new(Inactive {
            interface_name: self.interface_name.to_string(),
            filter: Some(packet_filter),
        })
    }

    fn start(self: Box<Self>, sender: Arc<Mutex<Sender<Event>>>) -> Box<dyn State> {
        let mut capture = Capture::from_device(self.interface_name.as_str())
            .expect("failed to open capture")
            .timeout(1000)
            .open()
            .expect("failed to activate capture");

        if let Some(filter) = &self.filter {
            capture
                .filter(filter.to_text().as_str(), false)
                .expect("failed to set filter program");
        }

        let filter = self.filter.clone();
        let _ = thread::spawn(move || loop {
            if let Ok(packet) = capture.next_packet() {
                let packet = PacketWrapper {
                    header: packet.header.clone(),
                    data: packet.data.to_vec(),
                    filter: filter.clone(),
                };
                sender
                    .lock()
                    .unwrap()
                    .send(Event::PacketReceived(packet))
                    .expect("failed to send received packet");
            }
        });
        Box::new(Active {})
    }
}

impl State for Active {
    fn filter(self: Box<Self>, _packet_filter: Filter) -> Box<dyn State> {
        self
    }

    fn start(self: Box<Self>, _sender: Arc<Mutex<Sender<Event>>>) -> Box<dyn State> {
        self
    }
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
    /// let filter = Filter::new().udp().port(67);
    /// ```
    ///
    /// is equivalent to:
    ///
    /// ```rust
    /// let filter = Filter::new().bootp_server_relay();
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
    /// let filter = Filter.new().udp().port(547);
    /// ```
    ///
    /// is equivalent to:
    ///
    /// ```rust
    /// let filter = Filter.new().dhcp_v6_server_relay();
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

#[cfg(test)]
mod tests {
    use crate::listener::{Filter, Proto};

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
}
