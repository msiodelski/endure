//! `time_wrapper` is a module providing a wrapper over a generic type
//! that carries a timestamp to be associated with the subject.
//!
//! A typical use case for this module is to stamp captured packets.
//! It allows for verifying and comparing packet reception times
//! during the audits. As a result, it is possible to measure things
//! like packet processing times.

use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Wraps an arbitrary value with a timestamp.
///
/// The generic argument is a type of the wrapped subject.
#[derive(Clone, Debug)]
pub struct TimeWrapper<T> {
    timestamp: SystemTime,
    subject: T,
}

impl<T> TimeWrapper<T>
where
    T: Clone + Debug,
{
    /// Instantiates the [`TimeWrapper`] using the UNIX epoch time.
    ///
    /// # Parameters
    ///
    /// - `timestamp` is the time since UNIX epoch time.
    /// - `subject` is the wrapped value to be associated with time.
    pub fn from_timeval(timestamp: libc::timeval, subject: T) -> Self {
        Self {
            timestamp: UNIX_EPOCH
                + Duration::new(timestamp.tv_sec as u64, timestamp.tv_usec as u32 * 1000),
            subject,
        }
    }

    /// Returns the timestamp.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Returns the wrapped subject.
    pub fn get(&self) -> &T {
        &self.subject
    }
}

impl<T> From<T> for TimeWrapper<T> {
    /// Converts the subject to `TimeWrapper`.
    ///
    /// The timestamp is set to the UNIX epoch start.
    fn from(subject: T) -> Self {
        Self {
            timestamp: UNIX_EPOCH,
            subject,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use libc::timeval;

    use super::TimeWrapper;

    #[test]
    fn time_wrapper_from_timeval() {
        let wrapper = TimeWrapper::from_timeval(
            timeval {
                tv_sec: 123,
                tv_usec: 222,
            },
            23,
        );
        assert!(wrapper.timestamp().gt(&UNIX_EPOCH));
        assert_eq!(23, wrapper.get().to_owned());
    }
}
