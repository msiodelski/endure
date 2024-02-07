# ChangeLog

## [Unreleased]

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

