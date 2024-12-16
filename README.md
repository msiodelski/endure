## Endure ![workflow](https://github.com/msiodelski/endure/actions/workflows/rust.yml/badge.svg)

Endure is a DHCP diagnostics utility installed next to a server or relay. It analyzes the inbound and outbound DHCP traffic and collects various diagnostic metrics. It can also be used for the capture file analysis.

### System and Software Requirements

Endure has been tested on Ubuntu 22 and macOS Sonoma 14.1.1. It requires [libpcap](https://www.tcpdump.org) library.

To compile the program on Ubuntu 22, first install `lib Ipcap-dev`:

```
$ apt install libpcap-dev
```

### Building with Cargo

Endure is written in [Rust](https://www.rust-lang.org) and can be compiled using the [cargo](https://doc.rust-lang.org/cargo/) utility. It was tested with `rustc` version is 1.82.

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

### Integration with Prometheus and Grafana

Endure source code includes a [Docker Compose](https://docs.docker.com/compose/) configuration that launches
two containers, one with a [Prometheus](https://prometheus.io) instance, and one with [Grafana](https://grafana.com).
This setup requires that [Host network driver](https://docs.docker.com/engine/network/drivers/host/) is enabled
in Docker.

Launch the containers using the following commands:

```
$ cd docker
$ docker compose up
```

Prometheus is configured to scrape the metrics from http://localhost:9100. Make sure that `endure`
makes the metrics available on that address and port. For example:

```
./endure collect --loopback  --prometheus --http-address 127.0.0.1:9100
```

Open Grafana dashboard in the browser on http://localhost:3000. Navigate to `Dashboards` to
monitor the metrics exported by `endure`.

### Capture File Analysis

Having a capture file named `capture.pcap` it is possible to gather the same metrics using the `read` command:

```
$ endure read --pcap capture.pcap --json
```

It will produce a report in the JSON format containing the metrics computed from all the DHCP packets in the capture file. The same report can be produced in the CSV format using the `--csv` switch.

Finally, using the `--stream` switch it is possible to generate a CSV output with several rows, each row presenting metrics for the number of packets specified using the `--sampling-window-size` switch. For example:

```
$ endure read --pcap capture.pcap --csv --stream --sampling-window-size 10
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
|`bootp_retransmit_percent`|Percentage of retransmissions|
|`bootp_retransmit_secs_avg`|Average number of seconds the DHCP clients have been retrying to acquire a lease|
|`bootp_retransmit_longest_trying_client`|MAC address of a client who has been trying to get the lease the longest|
|`dhcpv4_roundtrip_dora_milliseconds_avg`|Average time in milliseconds to complete a successful 4-way (DORA) exchange|
|`dhcpv4_roundtrip_dora_do_milliseconds_avg`|Average time in milliseconds to complete a Discover/Offer exchange during the 4-way (DORA) exchange|
|`dhcpv4_roundtrip_dora_ra_milliseconds_avg`|Average time in milliseconds to complete a Request/Ack exchange during the 4-way (DORA) exchange|

Many of the metrics listed above (e.g., average or percentages) are computed using
the last N packets. The default number of packets is 100 but can be changed to an
arbitrary value using the `--sampling-window-size` command line switch. The lower
the value the more dynamic are the metric changes over time. This parameter is not
applicable to the full `pcap` file analysis.

The metrics can be reported over several different channels: CSV write to a file or console, export to [Prometheus](prometheus.io), [Server Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events), or the REST API. Consult the [User's Manual](https://github.com/msiodelski/endure/wiki/User-Manual-(endure)) for details.

### License

Endure is licensed under the [MIT License](https://github.com/msiodelski/endure/blob/main/LICENSE).
