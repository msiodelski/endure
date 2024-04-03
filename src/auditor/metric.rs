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

/// Percentage of the `BootRequest` messages in last 100 messages.
pub const METRIC_OPCODE_BOOT_REQUESTS_PERCENT_100: &str = "opcode_boot_requests_percent_100";

/// Percentage of the `BootReply` messages in last 100 messages.
pub const METRIC_OPCODE_BOOT_REPLIES_PERCENT_100: &str = "opcode_boot_replies_percent_100";

/// Percentage of the invalid `BOOTP` message opcodes in last 100 messages.
pub const METRIC_OPCODE_INVALID_PERCENT_100: &str = "opcode_invalid_percent_100";

/// Percentage of the retransmissions in all messages.
pub const METRIC_RETRANSMIT_PERCENT: &str = "retransmit_percent";

/// Average value of the `secs` field in all retransmissions.
pub const METRIC_RETRANSMIT_SECS_AVG: &str = "retransmit_secs_avg";

/// Hardware address of the longest retrying client in all retransmissions.
pub const METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT: &str = "retransmit_longest_trying_client";

/// Percentage of the retransmissions in last 100 messages.
pub const METRIC_RETRANSMIT_PERCENT_100: &str = "retransmit_percent_100";

/// Average value of the `secs` field in last 100 retransmissions.
pub const METRIC_RETRANSMIT_SECS_AVG_100: &str = "retransmit_secs_avg_100";

/// Hardware address of the longest retrying client in last 100 retransmissions.
pub const METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT_100: &str =
    "retransmit_longest_trying_client_100";

/// Timestamp of the last analyzed packet.
pub const METRIC_PACKET_TIME_DATE_TIME: &str = "packet_time_date_time";
