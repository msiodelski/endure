## Endure ![workflow](https://github.com/msiodelski/endure/actions/workflows/rust.yml/badge.svg)

Endure is a DHCP diagnostics utility installed next to a server or relay. It analyzes the inbound and outbound DHCP traffic and collects various diagnostic metrics.

### System and Software Requirements

Endure has been tested on Ubuntu 22 and macOS Sonoma 14.1.1. Support for Microsoft Windows is planned. It requires [libpcap](https://www.tcpdump.org) library.

To compile the program on Ubuntu 22, first install `libpcap-dev` using the following command:

```
$ apt install libpcap-dev
```

### Building with Cargo

Endure is written in [Rust](https://www.rust-lang.org) and can be compiled using the [cargo](https://doc.rust-lang.org/cargo/) utility.

```
$ cd endure
$ cargo build
```

The resulting binary can be found in the `endure/target/debug` directory.

### Running the Utility

To run the utility and start listening on interfaces `bridge101` and `bridge102` run the following command:

```
$ endure collect -i bridge101 -i bridge102
```

You can specify as many interfaces as needed using the `-i` flag. Sometimes the DHCP servers operate on several interfaces.

### Metrics

Endure is a new project with limited capabilities. However, it can already collect and report several useful metrics:

| Metric | Description |
|--------|-------------|
|`opcode_boot_requests_percent`|A percentage of `BootRequest` packets|
|`opcode_boot_replies_percent`|A percentage of the `BootReply` packets|
|`opcode_invalid_percent`|A percentage of neither request nor reply packets|
|`retransmit_percent`|Percent of retransmissions|
|`retransmit_secs_avg`|Average number of seconds the DHCP clients have been retrying to acquire a lease|
|`retransmit_longest_trying_client`|MAC address of a client who has been trying to get the lease the longest|

The above metrics are calculated as a moving average from the last 100 packets.

The metrics are printed periodically into the `stdout` in the CSV format. It is the easiest format to generate and parse. Other formats, integration with databases will be available in the future releases.

### License

Endure is licensed under the [MIT License](https://github.com/msiodelski/endure/blob/main/LICENSE).
