## Endure ![workflow](https://github.com/msiodelski/endure/actions/workflows/rust.yml/badge.svg)

Endure is a DHCP diagnostics utility installed next to a server or relay. It analyzes the inbound and outbound DHCP traffic and collects various diagnostic metrics. It can also be used for the capture file analysis.

### System and Software Requirements

Endure has been tested on Ubuntu 22 and macOS Sonoma 14.1.1. It requires [libpcap](https://www.tcpdump.org) library.

To compile the program on Ubuntu 22, first install `lib Ipcap-dev`:

```
$ apt install libpcap-dev
```

### Building with Cargo

Endure is written in [Rust](https://www.rust-lang.org) and can be compiled using the [cargo](https://doc.rust-lang.org/cargo/) utility. The minimal required `rustc` version is 1.74.

```
$ cd endure
$ cargo build --release
```

The resulting binary can be found in the `endure/target/release` directory.

### Running the Utility

Suppose your DHCP server is responding to the traffic on the interfaces `bridge101` and `bridge102`.
You can start monitoring the server with the following command:

```
$ endure collect -i bridge101 -i bridge102 -c stdout
```

The `-c stdout` argument configures the program to output collected metrics into the console periodically.

Listening on the local loopback interface has no practical application in production, however it may be useful for testing purposes. The `--loopback` switch is an alias for the `-i [loopback name]` (e.g., `-i lo`). However, the `--loopback` argument cannot be combined with `-i`.

```
$ endure collect --loopback -c stdout
```

### Capture File Analysis

Having a capture file named `capture.pcap` it is possible to gather the same metrics using the `read` command:

```
$ endure read --pcap capture.pcap --json
```

It will produce a report in the JSON format containing the metrics computed from all the DHCP packets in the capture file. The same report can be produced in the CSV format using the `--csv` switch.

Finally, using the `--stream` switch it is possible to generate a CSV output with several rows, each row presenting metrics for the last 100 packets. For example:

```
$ endure read --pcap capture.pcap --csv --stream
```

### Metrics

Endure is a new project with limited capabilities. However, it can already collect and report several useful metrics:

| Metric | Description |
|--------|-------------|
|`bootp_opcode_boot_requests_count`|A total number of `BootRequest` messages|
|`bootp_opcode_boot_replies_count`|A total number of `BootRequest` messages|
|`bootp_opcode_invalid_count`|A total number of invalid messages (having invalid `OpCode`)|
|`bootp_opcode_boot_requests_percent`|A percentage of `BootRequest` messages|
|`bootp_opcode_boot_replies_percent`|A percentage of the `BootReply` messages|
|`bootp_opcode_invalid_percent`|A percentage of neither request nor reply messages|
|`bootp_opcode_boot_requests_percent_100`|A percentage of `BootRequest` messages in last 100 packets|
|`bootp_opcode_boot_replies_percent_100`|A percentage of the `BootReply` messages in last 100 packets|
|`bootp_opcode_invalid_percent_100`|A percentage of neither request nor reply messages in last 100 packets|
|`bootp_retransmit_percent`|Percentage of retransmissions|
|`bootp_retransmit_secs_avg`|Average number of seconds the DHCP clients have been retrying to acquire a lease|
|`bootp_retransmit_longest_trying_client`|MAC address of a client who has been trying to get the lease the longest|
|`bootp_retransmit_percent_100`|Percentage of retransmissions in last 100 packets|
|`bootp_retransmit_secs_avg_100`|Average number of seconds the DHCP clients have been retrying to acquire a lease in last 100 packets|
|`bootp_retransmit_longest_trying_client_100`|MAC address of a client who has been trying to get the lease the longest in last 100 packets|
|`dhcpv4_roundtrip_dora_milliseconds_avg`|Average time in milliseconds to complete a successful 4-way (DORA) exchange|
|`dhcpv4_roundtrip_dora_milliseconds_avg_100`|Average time in milliseconds to complete a successful 4-way (DORA) exchange for last 100 DHCPv4 transactions|

The metrics can be reported over several different channels: CSV write to a file or console, export to [Prometheus](prometheus.io), [Server Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events), or the REST API. Consult the [User's Manual](https://github.com/msiodelski/endure/wiki/User-Manual-(endure)) for details.

### License

Endure is licensed under the [MIT License](https://github.com/msiodelski/endure/blob/main/LICENSE).
