# ChangeLog

* Code refactoring required for collecting variable number of
  metrics depending on the selected profile. It introduces no
  new functionality to a user but is a necessary ground work
  for the `pcap` analysis. The only visible change to the user
  is that the metrics are now ordered alphabetically.
  (Github #47, #48).

* Implemented saving packet capture files.
  (Github #45, #46).

## Release v0.2.0 (Mar 13th, 2024)

* Added new metrics `opcode_boot_requests_total`,
  `opcode_boot_replies_total` and `opcode_invalid_total`.
  (Github #39, #40).

* Implemented basic CLI system tests. Specification of the
  interface name is now required. Added the --loopback switch
  for convenient selection of a loopback interface.
  (Github #36, #38).

* Support for capturing the bootp packets on the local loopback
  interface.
  (Github #33, #35).

* Enabled server sent events (SSE) endpoint returning periodic
  metrics reports.
  (Github #29, #31).

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

