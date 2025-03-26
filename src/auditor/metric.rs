//! `metric` module contains common declarations related to metrics.

/// Total number of broadcast messages.
pub const METRIC_BOOTP_CONVERSATION_BROADCAST_COUNT: &str = "bootp_conversation_broadcast_count";

/// Total number of relayed messages.
pub const METRIC_BOOTP_CONVERSATION_RELAYED_COUNT: &str = "bootp_conversation_relayed_count";

/// Total number of unicast not-relayed messages.
pub const METRIC_BOOTP_CONVERSATION_UNICAST_COUNT: &str = "bootp_conversation_unicast_count";

/// Percentage of broadcast messages.
pub const METRIC_BOOTP_CONVERSATION_BROADCAST_PERCENT: &str =
    "bootp_conversation_broadcast_percent";

/// Percentage of relayed messages.
pub const METRIC_BOOTP_CONVERSATION_RELAYED_PERCENT: &str = "bootp_conversation_relayed_percent";

/// Percentage of unicast not-relayed messages.
pub const METRIC_BOOTP_CONVERSATION_UNICAST_PERCENT: &str = "bootp_conversation_unicast_percent";

/// Total number of `BootRequest` messages.
pub const METRIC_BOOTP_OPCODE_BOOT_REQUESTS_COUNT: &str = "bootp_opcode_boot_requests_count";

/// Total number of `BootReply` messages.
pub const METRIC_BOOTP_OPCODE_BOOT_REPLIES_COUNT: &str = "bootp_opcode_boot_replies_count";

/// Total number of invalid `BOOTP` message opcodes.
pub const METRIC_BOOTP_OPCODE_INVALID_COUNT: &str = "bootp_opcode_invalid_count";

/// Percentage of the `BootRequest` messages.
pub const METRIC_BOOTP_OPCODE_BOOT_REQUESTS_PERCENT: &str = "bootp_opcode_boot_requests_percent";

/// Percentage of the `BootReply` messages.
pub const METRIC_BOOTP_OPCODE_BOOT_REPLIES_PERCENT: &str = "bootp_opcode_boot_replies_percent";

/// Percentage of the invalid `BOOTP` message opcodes.
pub const METRIC_BOOTP_OPCODE_INVALID_PERCENT: &str = "bootp_opcode_invalid_percent";

/// Timestamp of the last analyzed packet.
pub const METRIC_PACKET_TIME_DATE_TIME: &str = "packet_time_date_time";

/// Percentage of the retransmissions.
pub const METRIC_BOOTP_RETRANSMIT_PERCENT: &str = "bootp_retransmit_percent";

/// Average value of the `secs` field.
pub const METRIC_BOOTP_RETRANSMIT_SECS_AVG: &str = "bootp_retransmit_secs_avg";

/// Hardware address of the longest retrying client.
pub const METRIC_BOOTP_RETRANSMIT_LONGEST_TRYING_CLIENT: &str =
    "bootp_retransmit_longest_trying_client";

/// Average time in milliseconds to complete a successful 4-way (DORA) exchange.
pub const METRIC_DHCPV4_ROUNDTRIP_DORA_MILLISECONDS_AVG: &str =
    "dhcpv4_roundtrip_dora_milliseconds_avg";

/// Average time in milliseconds to complete a successful Discover/Offer exchange.
pub const METRIC_DHCPV4_ROUNDTRIP_DORA_DO_MILLISECONDS_AVG: &str =
    "dhcpv4_roundtrip_dora_do_milliseconds_avg";

/// Average time in milliseconds to complete a successful Request/Ack exchange
/// within a 4-way (DORA) exchange.
pub const METRIC_DHCPV4_ROUNDTRIP_DORA_RA_MILLISECONDS_AVG: &str =
    "dhcpv4_roundtrip_dora_ra_milliseconds_avg";
