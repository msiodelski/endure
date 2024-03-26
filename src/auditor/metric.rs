//! `metric` module contains common declarations related to metrics.

/// Total number of `BootRequest` messages.
pub const METRIC_OPCODE_BOOT_REQUESTS_COUNT: &str = "opcode_boot_requests_count";

/// Total number of `BootReply` messages.
pub const METRIC_OPCODE_BOOT_REPLIES_COUNT: &str = "opcode_boot_replies_count";

/// Total number of invalid `BOOTP` message opcodes.
pub const METRIC_OPCODE_INVALID_COUNT: &str = "opcode_invalid_count";

/// Percentage of the `BootRequest` messages in all messages.
pub const METRIC_OPCODE_BOOT_REQUESTS_PERCENT: &str = "opcode_boot_requests_percent";

/// Percentage of the `BootReply` messages in all messages.
pub const METRIC_OPCODE_BOOT_REPLIES_PERCENT: &str = "opcode_boot_replies_percent";

/// Percentage of the invalid `BOOTP` message opcodes in all messages.
pub const METRIC_OPCODE_INVALID_PERCENT: &str = "opcode_invalid_percent";

/// Percentage of the retransmissions.
pub const METRIC_RETRANSMIT_PERCENT: &str = "retransmit_percent";

/// Average value of the `secs` field in retransmissions.
pub const METRIC_RETRANSMIT_SECS_AVG: &str = "retransmit_secs_avg";

/// Hardware address of the longest retrying client.
pub const METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT: &str = "retransmit_longest_trying_client";
