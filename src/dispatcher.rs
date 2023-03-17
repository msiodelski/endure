//! dispatcher is a module serving as a core of the endure program.
//!
//! It installs the listeners and receives captured packets from them.
//! The dispatcher will eventually send the received packets to the
//! specialized modules for analysis. In this early version, it merely
//! prints the received packets in the binary form.
//!
//! # Example Usage
//!
//! The following snippet shows how to initialize and run the dispatcher
//! to capture DHCPv4 traffic on the bridge100 interface:
//!
//! ```rust
//! let mut dispatcher = dispatcher::Dispatcher::new();
//! let filter = Filter::new().bootp_server_relay();
//! dispatcher.add_listener("bridge100", filter).expect("listener already added");
//! dispatcher.dispatch();
//! ```


use std::{collections::HashMap, sync::{mpsc::{self, RecvTimeoutError}, Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};
use crate::listener::{Filter, Listener, PacketWrapper};

/// An atomic boolean value controlling program shutdown.
///
/// It is set to true when the program terminates after receiving a
/// signal (e.g., Ctrl-C). The [Dispatcher] monitors this value and
/// terminates when it is set to true.
///
/// ### Thread Safety
///
/// Accessing this value is thread-safe.
pub static STOP: AtomicBool = AtomicBool::new(false);

/// An enum of errors returned by the [Dispatcher].
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Returned on an attempt to add a duplicate listener.
    ///
    /// There must be at most one listener bound to an interface.
    /// An attempt to bind another listener to the same interface
    /// yields this error. It can be returned by the
    /// [Dispatcher::add_listener] function.
    AddListenerExists,
}

/// Runs the installed listeners until the stop signal occurs.
///
/// ### Future Work
///
/// Besides installing and running the listeners the dispatcher will
/// also be responsible for other IO operations in the future. In
/// particular, it will receive and process administrative commands.
pub struct Dispatcher {
    listeners: HashMap<String, Listener>,
}

impl Dispatcher {
    /// Instantiates the dispatcher.
    ///
    /// It creates an empty map of listeners. The caller should add
    /// the listeners using the [Dispatcher::add_listener] function.
    pub fn new() -> Dispatcher {
        Dispatcher{
            listeners: HashMap::new(),
        }
    }

    /// Attempts to add a listener for a device.
    ///
    /// The listener is installed for the specific device (i.e., interface).
    /// If there is another listener installed for this device already
    /// it returns [Error::AddListenerExists] error.
    ///
    /// The [Filter] applies filtering rules for packets capturing. For example,
    /// it can be used to filter only DHCPv4 packets, only UDP packets, select
    /// port number etc.
    pub fn add_listener(&mut self, interface_name: &str, filter: Filter) -> Result<(), Error> {
        if self.listeners.contains_key(interface_name) {
            return Err(Error::AddListenerExists)
        }
        let mut listener = Listener::new(interface_name);
        listener.filter(filter);
        self.listeners.insert(interface_name.to_string(), listener);
        Ok(())
    }

    /// Captures the packets using the installed listeners.
    ///
    /// It blocks until it observes that the [STOP] global value has been
    /// set to true.
    pub fn dispatch(&mut self) {
        let (tx, rx) = mpsc::channel::<PacketWrapper>();
        let tx = Arc::new(Mutex::new(tx));
        for listener in &mut self.listeners {
            listener.1.start(Arc::clone(&tx));
        }
        loop {
            if STOP.load(Ordering::Acquire) {
                self.stop();
                break;
            }
            match rx.recv_timeout(Duration::from_millis(1000)) {
                Ok(packet) => println!("received packet {:?}", packet),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    self.stop();
                    break
                }
            };
        }
    }

    /// Stops the listeners before exiting.
    fn stop(&mut self) {
        for listener in &mut self.listeners {
            listener.1.stop();
        }
        println!("stopped listeners");
    }
}


#[cfg(test)]
mod tests {
    use crate::dispatcher::{Dispatcher, Error::AddListenerExists};
    use crate::listener::Filter;

    #[test]
    fn add_listener() {
        let mut dispatcher = Dispatcher::new();
        let filter = Filter::new().udp();
        assert_eq!(dispatcher.add_listener("lo", filter), Ok(()));
        assert_eq!(dispatcher.add_listener("lo", Filter::new()), Err(AddListenerExists));
        assert_eq!(dispatcher.add_listener("lo0", Filter::new()), Ok(()));
        assert_eq!(dispatcher.listeners.len(), 2);
        assert!(dispatcher.listeners.contains_key("lo"));
        assert!(dispatcher.listeners.contains_key("lo0"));
        assert!(!dispatcher.listeners.contains_key("bridge"));
    }

    #[test]
    fn stop_not_started_listeners() {
        let mut dispatcher = Dispatcher::new();
        dispatcher.stop();
    }
}