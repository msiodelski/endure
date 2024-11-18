//! `proto` is a module holding the packets parsing logic for different
//! protocols.
//!
pub mod bootp;
pub mod buffer;
pub mod dhcp;

#[allow(missing_docs)]
#[cfg(test)]
pub mod tests;
