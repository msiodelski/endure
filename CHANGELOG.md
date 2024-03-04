# ChangeLog

* Enabled REST API endpoint for exporting the metrics as JSON.
  (Github #28, #30).

* Metrics export to Prometheus.
  (Github #26, #27).

## Release v0.1.0 (Feb 16th, 2024)

* The longest retransmitting DHCP client is reported in the
  metrics.
  (Github #19, #20).

* The metrics are reported with a single digit precision.
  (Github #14, #18).

* Selecting multiple interfaces for capturing the traffic from
  the command line with the `--interface-name` switch.
  (Github #13, #17).

* Implemented basic BOOTP packets analyzer with two auditors.
  The first auditor tracks the number of BootRequest, BootReply
  and invalid opcodes. The second auditor checks the percentage
  of retransmissions and an average secs field value in the
  client requests.
  (Github #11, #12).

* Implemented BOOTP packets parsing.
  (Github #9, #10).

* Implemented packet listeners and the dispatcher using the
  `pcap` library.
  (Github #3, #5).

