#![warn(missing_docs)]

//! endure is a DHCP diagnostics tool.

use std::{sync::atomic::Ordering, thread};
use graceful::SignalGuard;
use listener::Filter;

pub mod listener;
pub mod dispatcher;

fn main() {
    // Block the signals.
    let signal_guard = SignalGuard::new();

    // Run the dispatcher thread.
    let handle = thread::spawn(|| {
        let mut dispatcher = dispatcher::Dispatcher::new();
        let filter = Filter::new().bootp_server_relay();
        dispatcher.add_listener("wlo1", filter).expect("listener already added");
        dispatcher.dispatch();
    });

    // Wait for the signal to stop the dispatcher thread.
    signal_guard.at_exit(move |sig| {
        let signal_name: &str;
        match sig {
            2 => signal_name = "Ctrl+C",
            3 => signal_name = "QUIT signal",
            15 => signal_name = "SIGTERM signal",
            _ => signal_name = "signal",
        }
        println!("received {}", signal_name);
        println!("shutting down...");
        dispatcher::STOP.store(true, Ordering::Release);
        handle.join().unwrap();
    });
}
