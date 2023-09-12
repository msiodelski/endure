//! `thread` is a module providing generic multi-threading capabilities for the
//! application.

use crate::{listener::PacketWrapper, timer::Type};

/// `Event` is an enum used to transfer the data between a threads.
///
/// There are different types of events the threads can send. Events can
/// have specific data associated with them with the appropriate data formats.
/// For example, the [Event::PacketReceived] event includes the actual packet
/// data.
pub enum Event {
    /// Packet has been captured.
    PacketReceived(PacketWrapper),
    /// Periodic timer tick elapsed.
    TimerExpired(Type),
}
