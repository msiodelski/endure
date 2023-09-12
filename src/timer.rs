//! `timer` is a module providing a periodic timer functionality to other
//! crates in the application.
//!
//! The respective timers are registered with different intervals. The timer
//! thread observes when they elapse and communicates it to the main thread
//! via a channel. The elapsed timer is then rescheduled.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::{self};
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::thread::Event;

/// Represents errors returned by the timer manager functions.
#[derive(Debug, Error, PartialEq)]
pub enum Error {
    /// An error returned upon an attempt to register a timer that has
    /// already been registered.
    #[error("the timer {timer_type:?} has already been registered")]
    AlreadyRegistered {
        /// The registered timer type.
        timer_type: Type,
    },
}

/// Explicit list of timer types that can be used to register timers and
/// refer to them.
///
/// This list will grow when new timers are defined. It is possible to register
/// at most one timer of the given type.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Type {
    /// A timer executed to periodically gather the statistical information
    /// and make it available externally or log.
    DataScrape,
}

/// A state of an inactive timer manager.
///
/// When the timer manager holds this type of state it is stopped and exposes
/// the functions to register new timers. Running the timer manager with the
/// registered timers turns the timer manager to the [Active] state.
pub struct Inactive;

/// A state of an active (running) timer manager.
///
/// In this state it is not possible to register new timers.
pub struct Active;

/// A timer manager registers and runs all timers used in the program.
///
/// The timers can be registered when the timer manager is in the
/// [Inactive] state. Each timer has a [Type] and duration.
///
/// Internally, the timer manager runs its own thread that checks if
/// any of the timers have elapsed and sends notifications through a
/// channel provided by a caller. The caller should not expect that the
/// notifications will occur exactly at the specified time intervals.
/// They are usually slightly delayed.
pub struct TimerManager<State> {
    /// Hash map holding registered timers with their durations.
    timers: HashMap<Type, Duration>,
    /// Phantom data to suppress unused state type error.
    phantom: PhantomData<State>,
}

impl TimerManager<Inactive> {
    /// Instantiates an inactive timer manager.
    ///
    /// The caller can use this instance to register new timers.
    pub fn new() -> TimerManager<Inactive> {
        TimerManager::<Inactive> {
            timers: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Registers a timer in the timer manager.
    ///
    /// # Parameters
    ///
    /// - `timer_type` - an enum designating the timer to be registered.
    /// - `interval_ms` - timer's periodic interval in milliseconds.
    ///
    /// # Result
    ///
    /// It returns the [Error::AlreadyRegistered] error when the
    /// timer has been already registered.
    ///
    /// # Usage Note
    ///
    /// Register only one timer of the given type. An attempt to register
    /// more timers under the same type yields an error.
    pub fn register_timer(&mut self, timer_type: Type, interval_ms: u64) -> Result<(), Error> {
        if self.timers.contains_key(&timer_type) {
            return Err(Error::AlreadyRegistered {
                timer_type: timer_type,
            });
        }
        self.timers
            .insert(timer_type, Duration::from_millis(interval_ms));
        Ok(())
    }

    /// Puts the timer manager into the [Active] state.
    ///
    /// # Usage Note
    ///
    /// Call this function when all timers have been registered and you need
    /// to start the timers.
    pub fn into_active(self) -> TimerManager<Active> {
        TimerManager {
            timers: self.timers,
            phantom: PhantomData,
        }
    }
}

impl TimerManager<Active> {
    /// Runs the registered timers periodically.
    ///
    /// This function starts a worker thread that monitors when the timers
    /// elapse and notifies the caller over the channel. The channel conveys
    /// the elapsed timer's type.
    ///
    /// # Parameters
    ///
    /// - `sender` - a channel sender instance to be used by the manager to notify
    ///   about the elapsed timer ticks
    pub fn run(self, sender: Arc<Mutex<Sender<Event>>>) {
        // Start the thread.
        thread::spawn(move || {
            // Given the map of timers create a map of timer types mapped to the
            // timestamps of their next ticks.
            let mut ticks: HashMap<Type, Instant> = self
                .timers
                .iter()
                .map(|(t, d)| (t.to_owned(), Instant::now() + d.to_owned()))
                .collect();
            loop {
                // Go over the current list of ticks and see which of them have
                // already elapsed.
                let mut elapsed_types: Vec<Type> = Vec::new();
                ticks.iter().for_each(|tick| {
                    if tick.1.to_owned() <= Instant::now() {
                        elapsed_types.push(tick.0.to_owned());
                    }
                });
                // For each elapsed tick, send the notification to the caller.
                elapsed_types.iter().for_each(|elapsed_type| {
                    sender
                        .lock()
                        .unwrap()
                        .send(Event::TimerExpired(elapsed_type.to_owned()))
                        .expect("failed to send timer tick");
                    // Reschedule the ticks for the elapsed timers.
                    if let Some(duration) = self.timers.get(elapsed_type) {
                        ticks.insert(
                            elapsed_type.to_owned(),
                            Instant::now() + duration.to_owned(),
                        );
                    }
                });
                // Sort the new list of ticks by timestamps to see which one is next.
                let mut instants = ticks.values().collect::<Vec<&Instant>>();
                instants.sort();

                // Take the next tick and put the thread to sleep until then, so we don't
                // actively wait for the tick.
                match instants.first() {
                    Some(next_to_elapse) => {
                        if let Some(duration) =
                            next_to_elapse.checked_duration_since(Instant::now())
                        {
                            thread::sleep(duration);
                            continue;
                        }
                    }
                    // It seems impossible that we didn't manage to find a new tick but let's
                    // be safe. Schedule the next check in 1 second.
                    None => thread::sleep(Duration::from_millis(1000)),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::TimerManager;
    use crate::thread::Event;
    use std::{
        sync::{mpsc, Arc, Mutex},
        time::Duration,
    };

    #[test]
    fn register_timers() {
        let (tx, rx) = mpsc::channel::<Event>();
        let tx = Arc::new(Mutex::new(tx));
        let mut timer_mgr = TimerManager::new();
        let result = timer_mgr.register_timer(super::Type::DataScrape, 1);
        assert!(result.is_ok());
        let timer_mgr = timer_mgr.into_active();
        timer_mgr.run(Arc::clone(&tx));
        for _ in 0..10 {
            let tick = rx.recv_timeout(Duration::from_millis(5000));
            assert!(matches!(
                tick.unwrap(),
                Event::TimerExpired(super::Type::DataScrape)
            ));
        }
    }

    #[test]
    fn duplicate_timer() {
        let mut timer_mgr = TimerManager::new();
        let result = timer_mgr.register_timer(super::Type::DataScrape, 1);
        assert!(result.is_ok());
        let result = timer_mgr.register_timer(super::Type::DataScrape, 1);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "the timer DataScrape has already been registered"
        );
    }
}
