//! `analyzer` is a module containing the packet analysis and reporting logic.

use std::borrow::BorrowMut;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::{Mutex, RwLock};
use std::{fmt::Debug, sync::Arc};

use endure_lib::listener::{self, PacketWrapper};

use crate::proto::{bootp::OpCode, dhcp::v4};

use actix_web::HttpResponse;
use chrono::{DateTime, Local};
use prometheus_client::{collector::Collector, encoding::EncodeMetric, metrics::gauge::Gauge};
use serde::{Deserialize, Serialize};

use simple_moving_average::*;

/// A single record held in the [`MovingRanks`] container.
///
/// It contains an identifier, score and the age of the given rank.
///
/// # Generic Parameters
///
/// - `IDENT` - a unique rank identifier. It typically associates the rank
///   with a client (e.g., MAC address).
/// - `SCORE` - a score that can be compared with other ranks. It is a metric
///   associated with  a client (e.g., `secs` field value).
#[derive(Debug)]
struct MovingRank<IDENT, SCORE>
where
    SCORE: std::cmp::PartialOrd,
{
    /// A rank identifier.
    ///
    /// Typically a string value, such as client MAC address.
    id: IDENT,

    /// A metric used for scoring.
    ///
    /// Typically a number that can be compared with other numbers (ranks).
    /// The higher number is scored as a higher rank.
    score: SCORE,

    /// Score age.
    ///
    /// There is a limit in the [`MovingRanks`] how long the ranks are held.
    /// That's why an age of each rank has to be increased when a new score
    /// is reported. Newer scores eventually replace the older scores when
    /// their lifetime expires.
    age: usize,
}

impl<IDENT, SCORE> MovingRank<IDENT, SCORE>
where
    IDENT: std::cmp::PartialEq,
    SCORE: std::cmp::PartialOrd,
{
    /// Instantiates a new rank with an age of 0.
    ///
    /// # Parameters
    ///
    /// - `id` - rank identifier.
    /// - `score` - score to be ranked.
    fn new(id: IDENT, score: SCORE) -> MovingRank<IDENT, SCORE> {
        MovingRank { id, score, age: 0 }
    }
}

/// Tracks and holds the highest metrics associated with different clients.
///
/// # Generic Parameters
///
/// - `IDENT` - a unique rank identifier. It typically associates the rank
///   with a client (e.g., MAC address).
/// - `SCORE` - a score that can be compared with other ranks. It is a metric
///   associated with  a client (e.g., `secs` field value).
/// - `RANKS_NUM` - maximum number of the top ranks.
/// - `WINDOW_SIZE` - maximum age of the ranks until they expire.
///
/// # Usage Example
///
/// Suppose you want to track three clients with the longest retransmission
/// time (i.e., `secs` value). The [`MovingRanks`] can be used as follows:
///
/// ```rust
/// let mut ranks = MovingRanks::<String, u16, 3, 5>::new();
/// let secs: u16 = 15;
/// ranks.add_score("00:01:02:03:04:05".to_string(), secs);
/// if let Some(rank) = ranks.get(0) {
///     println!("{}", rank.id);
/// }
/// ```
/// The value of `5` in the generic parameters is the maximum age of the score.
/// Older ranks are removed and not taken into account when scoring. The value
/// of `3` is the maximum number of tracked ranks. The `u16` is the type of the
/// scored value. In this case the `secs` field is the two byte unsigned integer.
/// Finally, the `String` is the identifier type. Here, we represent the client
/// MAC address as a string.
#[derive(Debug)]
struct MovingRanks<IDENT, SCORE, const RANKS_NUM: usize, const WINDOW_SIZE: usize>
where
    IDENT: std::cmp::PartialEq,
    SCORE: std::cmp::PartialOrd,
{
    /// Stored ranks.
    ///
    /// This vector has a length between 0 and `RANKS_NUM`. The ranks can be
    /// retrieved using the [`MovingRanks::get_rank`] function.
    ranks: Vec<MovingRank<IDENT, SCORE>>,
}

impl<IDENT, SCORE, const RANKS_NUM: usize, const WINDOW_SIZE: usize>
    MovingRanks<IDENT, SCORE, RANKS_NUM, WINDOW_SIZE>
where
    IDENT: std::cmp::PartialEq,
    SCORE: std::cmp::PartialOrd,
{
    /// Instantiates the [`MovingRanks`].
    ///
    /// It creates an empty set of ranks.
    fn new() -> MovingRanks<IDENT, SCORE, RANKS_NUM, WINDOW_SIZE> {
        MovingRanks { ranks: Vec::new() }
    }

    /// Compares the score with the existing ranks and optionally puts it in the rank list.
    ///
    /// The [`MovingRanks`] keeps a limited number of ranks. If the score specified as
    /// a parameter is higher than any of the existing ranks the new score is preserved
    /// and the lowest score is removed. The scores are also removed when their lifetime
    /// ends (i.e., is greater than the `WINDOW_SIZE`). If the rank for the given identifier
    /// already exists it is replaced with a new score.
    ///
    /// # Parameters
    ///
    /// - `id` - a rank identifier (e.g., a client MAC address).
    /// - `score` - a value of the metrics (e.g., `secs` field value).
    fn add_score(&mut self, id: IDENT, score: SCORE) {
        // Remove expired scores.
        self.ranks
            .retain(|rank| rank.age < WINDOW_SIZE && rank.id != id);
        // Find the index in the vector where our new score belongs.
        let mut index: Option<usize> = None;
        for i in 0..self.ranks.len() {
            // Each sample in the vector gets an updated age.
            self.ranks[i].age += 1;
            if index.is_none() && score >= self.ranks[i].score {
                // The new score belongs at this position.
                index = Some(i);
            }
        }
        match index {
            Some(index) => {
                // Put the new rank between other ranks based on its score.
                self.ranks.insert(index, MovingRank::new(id, score));
                // In most cases we now have too many ranks. We need to remove one.
                if self.ranks.len() > RANKS_NUM {
                    self.ranks.drain(RANKS_NUM..);
                }
            }
            None => {
                // All the existing scores seem to be higher. In this case, we only
                // insert our score if we haven't filled the rank list yet.
                if self.ranks.len() < RANKS_NUM {
                    self.ranks.push(MovingRank::new(id, score));
                }
            }
        }
    }

    /// Returns a specified rank by index.
    ///
    /// # Parameters
    ///
    /// - index - rank index. The index of `0` is the highest rank.
    ///
    /// # Returned Value
    ///
    /// If the specified index is greater than the number of ranks this function
    /// returns `None`. Otherwise, it returns a specified rank where `0` means the
    /// highest rank.
    fn get_rank(&self, index: usize) -> Option<&MovingRank<IDENT, SCORE>> {
        self.ranks.get(index)
    }
}

/// Simple moving average for calculating percentages of several related metrics.
///
/// There are some groups of metrics that have to be tracked together, each being
/// a portion of 100%. For example, an auditor calculating BootRequest, BootReply
/// and invalid messages tracks the percentages of these three message types in
/// all analyzed massages. That's exactly the use case for the [`PercentSMA`].
///
/// # Generic Parameters
///
/// - `METRICS_NUM` - specifies the number of tracked metrics. In the case
///    described above, it will be `3`.
/// - `WINDOW_SIZE` - specifies the size of the moving average window.
///
/// # Precision
///
/// The average percentages are returned as floating point number with one
/// decimal digit. The implementation is using `u64` internally.
#[derive(Clone, Copy, Debug)]
struct PercentSMA<const METRICS_NUM: usize, const WINDOW_SIZE: usize> {
    averages: [NoSumSMA<u64, u64, WINDOW_SIZE>; METRICS_NUM],
}

impl<const METRICS_NUM: usize, const WINDOW_SIZE: usize> PercentSMA<METRICS_NUM, WINDOW_SIZE> {
    /// Instantiates the [`PercentSMA`].
    fn new() -> PercentSMA<METRICS_NUM, WINDOW_SIZE> {
        PercentSMA {
            averages: [(); METRICS_NUM].map(|_| NoSumSMA::new()),
        }
    }

    /// Increases a selected metric by `1`.
    ///
    /// # Parameters
    ///
    /// - metric_index - an index of a metric to increase.
    ///
    /// # Usage Example
    ///
    /// Call this function when one of the metrics needs to be increased by
    /// one. For example, when a `BootRequest` message arrives, call this
    /// function to increase the number of received `BootRequest` messages.
    /// Internally, the function also adds the `0` sample to the remaining metrics.
    /// This effectively reduces the quota of the remaining metrics and increases
    /// the quota of the selected metric.
    fn increase(&mut self, metric_index: usize) {
        for i in 0..METRICS_NUM {
            if i == metric_index {
                // Add a sample of `1` to a selected metric.
                self.averages[i].add_sample(1000);
            } else {
                // Add a sample of `0` of the remaining mretrics.
                self.averages[i].add_sample(0);
            }
        }
    }

    /// Return the moving average of the selected metric.
    ///
    /// # Parameters
    ///
    /// - metric_index - an index of the metric to return.
    ///
    /// # Returned Value
    ///
    /// The returned value is a percentage of all samples added to the specified
    /// metric. The sum of the averages returned by this function for all metrics
    /// is roughly equal to 100%. The returned value has a single decimal precision.
    fn average(self, metric_index: usize) -> f64 {
        self.averages[metric_index].get_average() as f64 / 10f64
    }
}

/// A moving average implementation with an arbitrary precision.
///
/// It is a wrapper around the [`NoSumSMA`] returning an average as a floating
/// point number with an arbitrary precision.
///
/// # Generic Parameters
///
/// - PRECISION - selected precision (i.e., 10 for single decimal, 100 for two decimals
///   1000 for three, etc.)
/// - `WINDOW_SIZE` - specifies the size of the moving average window.
#[derive(Clone, Copy, Debug)]
struct RoundedSMA<const PRECISION: usize, const WINDOW_SIZE: usize> {
    sma: NoSumSMA<u64, u64, WINDOW_SIZE>,
}

impl<const PRECISION: usize, const WINDOW_SIZE: usize> RoundedSMA<PRECISION, WINDOW_SIZE> {
    /// Instantiates the [`RoundedSMA`].
    fn new() -> RoundedSMA<PRECISION, WINDOW_SIZE> {
        RoundedSMA {
            sma: NoSumSMA::new(),
        }
    }

    /// Adds a sample.
    ///
    /// # Parameters
    ///
    /// - sample - a sample value.
    fn add_sample(&mut self, sample: u64) {
        self.sma.add_sample(PRECISION as u64 * sample);
    }

    /// Returns an average with a selected precision.
    fn average(self) -> f64 {
        self.sma.get_average() as f64 / PRECISION as f64
    }
}

/// A structure receiving a current report from the DHCPv4 auditors.
///
/// The [`Analyzer::current_dhcpv4_report`] function takes this structure
/// as a parameter and the DHCPv4 auditors are responsible for filling
/// their respective fields with the current audit results.
///
/// The structure must be extended with additional fields for new auditors,
/// when they are implemented.
///
/// The report is serialized to the CSV format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHCPv4Report {
    /// Report generation time.
    ///
    /// The value of this field is generated by the [`Analyzer`] when it receives
    /// the reports from the auditors. The auditors must not modify this field.
    time: DateTime<Local>,
    /// Total number of the received `BootRequest` messages.
    ///
    /// This metric is maintained by the [`OpCodeAuditor`].
    opcode_boot_requests_count: i64,
    /// Total number of the received `BootReply` messages.
    ///
    /// This metric is maintained by the [`OpCodeAuditor`].
    opcode_boot_replies_count: i64,
    /// Total number of the received invalid messages.
    ///
    /// This metric is maintained by the [`OpCodeAuditor`].
    opcode_invalid_count: i64,
    /// Percentage of the received `BootRequest` messages.
    ///
    /// This metric is maintained by the [`OpCodeAuditor`].
    opcode_boot_requests_percent: f64,
    /// Percentage of the received `BootReply` messages.
    ///
    /// This metric is maintained by the [`OpCodeAuditor`].
    opcode_boot_replies_percent: f64,
    /// Percentage of the messages with an invalid `opcode`.
    ///
    /// An invalid field is neither `BootRequest` nor `BootReply`.
    /// This metric is maintained by the [`OpCodeAuditor`].
    opcode_invalid_percent: f64,
    /// Percentage of the DHCPv4 client retransmissions.
    ///
    /// It indicates how many percent of the received `BootRequest` messages
    /// have an elevated `secs` field value.
    ///
    /// This metric is maintained by the [`RetransmissionAuditor`].
    retransmit_percent: f64,
    /// Average `secs` field value in the received client messages.
    ///
    /// This metric is maintained by the [`RetransmissionAuditor`].
    retransmit_secs_avg: f64,
    /// A hardware address of the client with the largest `secs` value.
    ///
    /// This metric is maintained by the [`RetransmissionAuditor`].
    retransmit_longest_trying_client: String,
}

impl DHCPv4Report {
    /// Instantiates new report.
    ///
    /// It sets default values to all metrics. It also sets the current
    /// time for the [`DHCPv4Report::time`] field.
    fn new() -> DHCPv4Report {
        DHCPv4Report {
            time: Local::now(),
            opcode_boot_requests_count: 0,
            opcode_boot_replies_count: 0,
            opcode_invalid_count: 0,
            opcode_boot_requests_percent: 0.0,
            opcode_boot_replies_percent: 0.0,
            opcode_invalid_percent: 0.0,
            retransmit_percent: 0.0,
            retransmit_secs_avg: 0.0,
            retransmit_longest_trying_client: String::new(),
        }
    }

    /// Serializes the [`DHCPv4Report`] to a JSON string.
    ///
    /// # Errors
    ///
    /// Any occurrence of the serialization error is unlikely in the well
    /// defined structure like this one, and is an implementation error.
    /// Thus, errors are swallowed.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap_or_default()
    }
}

impl Default for DHCPv4Report {
    fn default() -> Self {
        DHCPv4Report::new()
    }
}

/// A trait that must be implemented by each DHCPv4 auditor.
///
/// The [`Analyzer`] calls the [`DHCPv4PacketAuditor::audit`] function
/// for each received BOOTP packet. The auditor runs specialized
/// checks on the packet and updates its local state and maintained
/// metrics. The [`Analyzer`] can call [`DHCPv4PacketAuditor::receive_report`]
/// to gather the metrics from the auditor periodically.
pub trait DHCPv4PacketAuditor: Debug + Send + Sync {
    /// Runs an audit on the received packet.
    ///
    /// The audit is specific to the given auditor implementing this
    /// trait. The auditor maintains some specific metrics gathered
    /// from the constant analysis of the received packets. It may
    /// discard some of the packets that don't meet the audit criteria.
    ///
    /// For example: an auditor checking client retransmissions should
    /// ignore the replies from the server and return immediately.
    ///
    /// # Parameters
    ///
    /// - `packet` - a partially parsed `DHCPv4` or `BOOTP` packet to be audited
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>);

    /// Reports auditor's metrics in the global report to the [`Analyzer`].
    ///
    /// This function is called by the [`Analyzer`] for each auditor. The
    /// auditor should respond by returning its metrics in the provided
    /// `report`.
    ///
    /// # Parameters
    ///
    /// - `report` - mutable reference to the report in which the auditor
    ///              is supposed to set its metrics
    fn receive_report(&mut self, report: &mut DHCPv4Report);
}

/// A central instance receiving the captured packets and performing their
/// analysis using available auditors.
///
/// It recognizes received packet types and selects appropriate auditors
/// to perform the analysis.
#[derive(Clone, Debug)]
pub struct Analyzer {
    auditors: Arc<Mutex<AnalyzerAuditorsState>>,
    last_report: Arc<RwLock<DHCPv4Report>>,
}

#[derive(Debug, Default)]
struct AnalyzerAuditorsState {
    dhcpv4_auditors: Vec<Box<dyn DHCPv4PacketAuditor>>,
}

impl Analyzer {
    /// Instantiates the [`Analyzer`].
    pub fn new() -> Self {
        Self {
            auditors: Arc::new(Mutex::new(AnalyzerAuditorsState::default())),
            last_report: Arc::new(RwLock::new(DHCPv4Report::new())),
        }
    }

    /// Installs all default auditors.
    pub fn add_default_auditors(&mut self) {
        self.auditors
            .lock()
            .unwrap()
            .dhcpv4_auditors
            .push(RetransmissionAuditor::new());
        self.auditors
            .lock()
            .unwrap()
            .dhcpv4_auditors
            .push(OpCodeAuditor::new());
    }

    /// Runs analysis of the received packet.
    ///
    /// It checks the packet type and picks appropriate set of auditors
    /// for the analysis.
    ///
    /// # Parameters
    ///
    /// - `packet` - a wrapper containing the captured packet and its metadata
    pub fn receive<'a>(&mut self, packet: PacketWrapper) {
        match packet.filter {
            Some(filter) => match filter.get_proto() {
                Some(listener::Proto::Bootp) => {
                    let packet_payload = packet.payload();
                    match packet_payload {
                        Ok(packet_payload) => {
                            let packet_payload = v4::ReceivedPacket::new(&packet_payload);
                            self.audit_dhcpv4(&packet_payload);
                        }
                        // For now we ignore unsupported data links or truncated packets.
                        _ => {}
                    }
                }
                _ => {}
            },
            None => {}
        }
    }

    /// Audits a DHCPv4 packet.
    ///
    /// # Parameters
    ///
    /// - `packet` - a received unparsed DHCPv4 packet
    fn audit_dhcpv4<'a>(&mut self, packet: &v4::RawPacket<'a>) {
        let mut packet = packet.into_parsable();
        for auditor in self.auditors.lock().unwrap().dhcpv4_auditors.iter_mut() {
            auditor.audit(&mut packet);
            auditor.receive_report(self.last_report.write().unwrap().borrow_mut());
        }
    }

    /// Returns the current report from all DHCPv4 auditors.
    ///
    /// # Usage
    ///
    /// Typically, this function is called periodically to make the report
    /// available to an external reader (e.g., to append the report as a
    /// row of a CSV file or to a Prometheus exporter).
    pub fn current_dhcpv4_report(&self) -> DHCPv4Report {
        self.last_report.read().unwrap().clone()
    }

    /// Returns a current metrics report as HTTP response.
    ///
    /// This function is called directly from the HTTP server handler returning
    /// the entire report as a JSON string.
    ///
    /// # Errors
    ///
    /// This function returns no errors.
    pub async fn http_encode_to_json(&self) -> actix_web::Result<HttpResponse> {
        let report = self.current_dhcpv4_report();
        Ok(HttpResponse::Ok()
            .content_type("application/json")
            .body(report.to_json()))
    }
}

impl Collector for Analyzer {
    fn encode(
        &self,
        mut encoder: prometheus_client::encoding::DescriptorEncoder,
    ) -> Result<(), std::fmt::Error> {
        let last_report = &self.last_report.read().unwrap();

        let gauge = Gauge::<i64, AtomicI64>::default();
        gauge.set(last_report.opcode_boot_requests_count);
        let metric_encoder = encoder.encode_descriptor(
            "opcode_boot_requests_total",
            "Total number of the BootRequest messages.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<i64, AtomicI64>::default();
        gauge.set(last_report.opcode_boot_replies_count);
        let metric_encoder = encoder.encode_descriptor(
            "opcode_boot_replies_total",
            "Total number of the BootReply messages.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<i64, AtomicI64>::default();
        gauge.set(last_report.opcode_invalid_count);
        let metric_encoder = encoder.encode_descriptor(
            "opcode_boot_replies_total",
            "Total number of the invalid messages.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<f64, AtomicU64>::default();
        gauge.set(last_report.opcode_boot_requests_percent);
        let metric_encoder = encoder.encode_descriptor(
            "opcode_boot_requests_percent",
            "Percentage of the BootRequest messages.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<f64, AtomicU64>::default();
        gauge.set(last_report.opcode_boot_replies_percent);
        let metric_encoder = encoder.encode_descriptor(
            "opcode_boot_replies_percent",
            "Percentage of the BootReply messages.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<f64, AtomicU64>::default();
        gauge.set(last_report.opcode_invalid_percent);
        let metric_encoder = encoder.encode_descriptor(
            "opcode_invalid_percent",
            "Percentage of the invalid messages.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<f64, AtomicU64>::default();
        gauge.set(last_report.retransmit_percent);
        let metric_encoder = encoder.encode_descriptor(
            "retransmit_percent",
            "Percentage of the retransmissions in the mssages sent by clients.",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        let gauge = Gauge::<f64, AtomicU64>::default();
        gauge.set(last_report.retransmit_secs_avg);
        let metric_encoder = encoder.encode_descriptor(
            "retransmit_secs_avg",
            "Average retransmission time (i.e. average time in retransmissions to acquire a new lease).",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;

        Ok(())
    }
}

/// An auditor maintaining the statistics of the `BOOTP` message types.
///
/// It recognizes `BootRequest` and `BootReply` messages and maintains
/// an average percentage of each message type in the received packets
/// stream.
///
/// # Metrics
///
/// Keeping track of the `BootRequest` and `BootReply` message types can
/// be useful to detect situations when a DHCP server is unable to keep up
/// with the traffic. Another extreme case is when the are only `BootRequest`
/// messages and no `BootReply`. It indicates that the server is down
/// or misconfigured.
///
/// The auditor also returns an average number of invalid messages
/// (i.e., neither `BootRequest` nor `BootReply`).
#[derive(Clone, Copy, Debug)]
pub struct OpCodeAuditor {
    requests_count: i64,
    replies_count: i64,
    invalid_count: i64,
    opcodes: PercentSMA<3, 100>,
}

impl OpCodeAuditor {
    /// Instantiates the [`OpCodeAuditor`].
    pub fn new() -> Box<dyn DHCPv4PacketAuditor> {
        Box::new(OpCodeAuditor {
            requests_count: 0,
            replies_count: 0,
            invalid_count: 0,
            opcodes: PercentSMA::new(),
        })
    }
}

impl DHCPv4PacketAuditor for OpCodeAuditor {
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>) {
        match packet.opcode() {
            Ok(opcode) => match opcode {
                OpCode::BootRequest => {
                    self.requests_count += 1;
                    self.opcodes.increase(0usize);
                }
                OpCode::BootReply => {
                    self.replies_count += 1;
                    self.opcodes.increase(1usize);
                }
                OpCode::Invalid(_) => {
                    self.invalid_count += 1;
                    self.opcodes.increase(2usize);
                }
            },
            Err(_) => {}
        };
    }

    fn receive_report(&mut self, report: &mut DHCPv4Report) {
        report.opcode_boot_requests_count = self.requests_count;
        report.opcode_boot_replies_count = self.replies_count;
        report.opcode_invalid_count = self.invalid_count;
        report.opcode_boot_requests_percent = self.opcodes.average(0);
        report.opcode_boot_replies_percent = self.opcodes.average(1);
        report.opcode_invalid_percent = self.opcodes.average(2);
    }
}

/// An auditor maintaining the statistics of DHCP retransmissions.
///
/// The auditor looks into the `secs` field of the `BOOTP` messages. If this
/// field has a value greater than zero it indicates that the client has been
/// unable to allocate a lease in the previous attempts and retransmits.
///
/// # Metrics
///
/// Client retransmissions often occur when the server is unable to keep up
/// with the DHCP traffic load. A high average value of the `secs` field and
/// a high average number of retransmissions indicate that the server has
/// hard time to keep up with the traffic.
///
/// The auditor also keeps track of the MAC address of the client who has been
/// trying to get a lease for a longest period of time in last 1000 packets.
#[derive(Debug)]
pub struct RetransmissionAuditor {
    retransmits: RoundedSMA<10, 100>,
    secs: RoundedSMA<10, 100>,
    longest_trying_client: MovingRanks<String, u16, 1, 100>,
}

impl RetransmissionAuditor {
    /// Instantiates the [`RetransmissionAuditor`].
    pub fn new() -> Box<dyn DHCPv4PacketAuditor> {
        Box::new(RetransmissionAuditor {
            retransmits: RoundedSMA::new(),
            secs: RoundedSMA::new(),
            longest_trying_client: MovingRanks::new(),
        })
    }
}

impl DHCPv4PacketAuditor for RetransmissionAuditor {
    fn audit<'a>(&mut self, packet: &mut v4::PartiallyParsedPacket<'a>) {
        let opcode = packet.opcode();
        if opcode.is_err() || opcode.is_ok() && opcode.unwrap().ne(&OpCode::BootRequest) {
            return;
        }
        match packet.secs() {
            Ok(secs) => {
                if secs > 0 {
                    // Since we want the percentage rather than the average between 0 and 1,
                    // let's add 100 (instead of 1), so we get appropriate precision and we
                    // don't have to multiply the resulting average by 100 later on.
                    self.retransmits.add_sample(100u64);
                    // Get the client's hardware address.
                    match packet.chaddr() {
                        Ok(haddr) => {
                            self.longest_trying_client
                                .add_score(haddr.to_string(), secs);
                        }
                        Err(_) => {}
                    }
                } else {
                    self.retransmits.add_sample(0u64);
                }
                self.secs.add_sample(secs as u64);
            }
            Err(_) => {}
        };
    }

    fn receive_report(&mut self, report: &mut DHCPv4Report) {
        report.retransmit_percent = self.retransmits.average();
        report.retransmit_secs_avg = self.secs.average();
        if let Some(longest_trying_client) = self.longest_trying_client.get_rank(0) {
            report.retransmit_longest_trying_client = longest_trying_client.id.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{body::to_bytes, web::Bytes};
    use assert_json::assert_json;
    use pcap::{Linktype, PacketHeader};
    use prometheus_client::{encoding::text::encode, registry::Registry};

    use super::{Analyzer, DHCPv4Report, MovingRanks, OpCodeAuditor, RoundedSMA};
    use crate::{
        analyzer::RetransmissionAuditor,
        proto::{bootp::*, dhcp::v4::ReceivedPacket, tests::common::TestBootpPacket},
    };
    use endure_lib::listener::{self, PacketWrapper};

    trait BodyTest {
        fn as_str(&self) -> &str;
    }

    impl BodyTest for Bytes {
        fn as_str(&self) -> &str {
            std::str::from_utf8(self).unwrap()
        }
    }

    /// A convenience function testing the returned rank.
    fn expect_rank(
        ranks: &MovingRanks<String, u64, 3, 5>,
        index: usize,
        id: &str,
        score: u64,
        age: usize,
    ) {
        let rank = ranks.get_rank(index);
        assert!(rank.is_some());
        assert_eq!(id, rank.unwrap().id);
        assert_eq!(score, rank.unwrap().score);
        assert_eq!(age, rank.unwrap().age);
    }

    #[test]
    fn ranks() {
        let mut ranks = MovingRanks::<String, u64, 3, 5>::new();
        assert!(ranks.get_rank(0).is_none());

        ranks.add_score("foo".to_string(), 20);
        expect_rank(&ranks, 0, "foo", 20, 0);
        assert!(ranks.get_rank(1).is_none());

        ranks.add_score("bar".to_string(), 40);
        ranks.add_score("baz".to_string(), 10);

        expect_rank(&ranks, 0, "bar", 40, 1);
        expect_rank(&ranks, 1, "foo", 20, 2);
        expect_rank(&ranks, 2, "baz", 10, 0);

        ranks.add_score("bac".to_string(), 5);

        expect_rank(&ranks, 0, "bar", 40, 2);
        expect_rank(&ranks, 1, "foo", 20, 3);
        expect_rank(&ranks, 2, "baz", 10, 1);

        ranks.add_score("bar".to_string(), 50);

        expect_rank(&ranks, 0, "bar", 50, 0);
        expect_rank(&ranks, 1, "foo", 20, 4);
        expect_rank(&ranks, 2, "baz", 10, 2);

        ranks.add_score("cab".to_string(), 30);

        expect_rank(&ranks, 0, "bar", 50, 1);
        expect_rank(&ranks, 1, "cab", 30, 0);
        expect_rank(&ranks, 2, "foo", 20, 5);

        ranks.add_score("aaa".to_string(), 5);

        expect_rank(&ranks, 0, "bar", 50, 2);
        expect_rank(&ranks, 1, "cab", 30, 1);
        expect_rank(&ranks, 2, "aaa", 5, 0);

        ranks.add_score("bar".to_string(), 1);

        expect_rank(&ranks, 0, "cab", 30, 2);
        expect_rank(&ranks, 1, "aaa", 5, 1);
        expect_rank(&ranks, 2, "bar", 1, 0);
    }

    #[test]
    fn rounded_average_prec10() {
        let mut avg = RoundedSMA::<10, 100>::new();
        avg.add_sample(1);
        assert_eq!(1.0, avg.average());
        avg.add_sample(1);
        assert_eq!(1.0, avg.average());
        avg.add_sample(2);
        assert_eq!(1.3, avg.average());
        avg.add_sample(8);
        assert_eq!(3.0, avg.average());
    }

    #[test]
    fn rounded_average_prec100() {
        let mut avg = RoundedSMA::<100, 100>::new();
        avg.add_sample(1);
        assert_eq!(1.0, avg.average());
        avg.add_sample(0);
        assert_eq!(0.5, avg.average());
        avg.add_sample(1);
        assert_eq!(0.66, avg.average());
        avg.add_sample(8);
        assert_eq!(2.5, avg.average());
    }

    #[test]
    fn rounded_average_window_size() {
        let mut avg = RoundedSMA::<10, 2>::new();
        avg.add_sample(1);
        assert_eq!(1.0, avg.average());
        avg.add_sample(0);
        assert_eq!(0.5, avg.average());
        avg.add_sample(1);
        assert_eq!(0.5, avg.average());
        avg.add_sample(1);
        assert_eq!(1.0, avg.average());
        avg.add_sample(0);
        assert_eq!(0.5, avg.average());
        avg.add_sample(0);
        assert_eq!(0.0, avg.average());
    }

    #[test]
    fn report_to_json() {
        let report = DHCPv4Report::default();
        let json = report.to_json();
        assert_json!(json.as_ref(), { "opcode_boot_replies_percent": 0.0 });
    }

    #[test]
    fn receive_dhcp4_packet_ethernet() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        let mut packet_wrapper = PacketWrapper {
            filter: Some(listener::Filter::new().bootp(10067)),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::ETHERNET,
        };
        // The packet is now filled with zeros. Set the first byte of the payload
        // to 1. It makes the packet a BootRequest. If it is successfully audited
        // we should see the metrics to be bumped up.
        packet_wrapper.data[listener::ETHERNET_IP_UDP_HEADER_LENGTH] = 1;
        analyzer.receive(packet_wrapper);
        let report = analyzer.current_dhcpv4_report();
        assert_eq!(100.0, report.opcode_boot_requests_percent);
    }

    #[test]
    fn receive_dhcp4_packet_loopback() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        let mut packet_wrapper = PacketWrapper {
            filter: Some(listener::Filter::new().bootp(10067)),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::NULL,
        };
        // The packet is now filled with zeros. Set the first byte of the payload
        // to 1. It makes the packet a BootRequest. If it is successfully audited
        // we should see the metrics to be bumped up.
        packet_wrapper.data[listener::LOOPBACK_IP_UDP_HEADER_LENGTH] = 1;
        analyzer.receive(packet_wrapper);
        let report = analyzer.current_dhcpv4_report();
        assert_eq!(100.0, report.opcode_boot_requests_percent);
    }

    #[test]
    fn receive_dhcp4_packet_non_matching_filter() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        let mut packet_wrapper = PacketWrapper {
            filter: Some(listener::Filter::new().udp()),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 100],
            data_link: Linktype::ETHERNET,
        };
        packet_wrapper.data[listener::ETHERNET_IP_UDP_HEADER_LENGTH] = 1;
        analyzer.receive(packet_wrapper);
        let report = analyzer.current_dhcpv4_report();
        // The packet shouldn't be analyzed and the metrics should not
        // be updated.
        assert_eq!(0.0, report.opcode_boot_requests_percent);
    }

    #[test]
    fn receive_dhcp4_packet_truncated() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        let packet_wrapper = PacketWrapper {
            filter: Some(listener::Filter::new().udp()),
            header: PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                len: 0,
            },
            data: vec![0; 15],
            data_link: Linktype::ETHERNET,
        };
        analyzer.receive(packet_wrapper);
        let report = analyzer.current_dhcpv4_report();
        assert_eq!(0.0, report.opcode_boot_requests_percent);
    }

    #[test]
    fn dhcpv4_analysis() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        for i in 0..10 {
            let test_packet = TestBootpPacket::new();
            let test_packet = test_packet
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = ReceivedPacket::new(&test_packet.get());
            analyzer.audit_dhcpv4(&packet);
        }
        let report = analyzer.current_dhcpv4_report();
        assert_eq!(0.0, report.opcode_boot_replies_percent);
        assert_eq!(100.0, report.opcode_boot_requests_percent);
        assert_eq!(0.0, report.opcode_invalid_percent);
        assert_eq!(90.0, report.retransmit_percent);
        assert_eq!(4.5, report.retransmit_secs_avg);
        assert_eq!("2d:20:59:2b:0c:16", report.retransmit_longest_trying_client);
    }

    #[test]
    fn opcode_audit() {
        let mut auditor = OpCodeAuditor::new();
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet.set(OPCODE_POS, &vec![1]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        // Audit 5 request packets. They should constitute 100% of all packets.
        for _ in 0..5 {
            auditor.audit(packet);
        }
        let mut report = DHCPv4Report::new();
        auditor.receive_report(&mut report);
        assert_eq!(5, report.opcode_boot_requests_count);
        assert_eq!(0, report.opcode_boot_replies_count);
        assert_eq!(0, report.opcode_invalid_count);
        assert_eq!(100.0, report.opcode_boot_requests_percent);
        assert_eq!(0.0, report.opcode_boot_replies_percent);
        assert_eq!(0.0, report.opcode_invalid_percent);

        // Audit 3 reply packets. Now we have 8 packets audited (62.5% are requests and 37.5%
        // are replies).
        let test_packet = test_packet.set(OPCODE_POS, &vec![2]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..3 {
            auditor.audit(packet);
        }
        auditor.receive_report(&mut report);
        assert_eq!(5, report.opcode_boot_requests_count);
        assert_eq!(3, report.opcode_boot_replies_count);
        assert_eq!(0, report.opcode_invalid_count);
        assert_eq!(62.5, report.opcode_boot_requests_percent);
        assert_eq!(37.5, report.opcode_boot_replies_percent);
        assert_eq!(0.0, report.opcode_invalid_percent);

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (50% of requests, 30% of replies and 20% invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![3]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..2 {
            auditor.audit(packet);
        }
        auditor.receive_report(&mut report);
        assert_eq!(5, report.opcode_boot_requests_count);
        assert_eq!(3, report.opcode_boot_replies_count);
        assert_eq!(2, report.opcode_invalid_count);
        assert_eq!(50.0, report.opcode_boot_requests_percent);
        assert_eq!(30.0, report.opcode_boot_replies_percent);
        assert_eq!(20.0, report.opcode_invalid_percent);
    }

    #[test]
    fn retransmissions_audit() {
        let mut auditor = RetransmissionAuditor::new();
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![1])
            .set(SECS_POS, &vec![0, 0]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();

        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        auditor.audit(packet);
        let mut report = DHCPv4Report::new();
        auditor.receive_report(&mut report);
        assert_eq!(0.0, report.retransmit_percent);
        assert_eq!(0.0, report.retransmit_secs_avg);
        assert_eq!("", report.retransmit_longest_trying_client);

        // Audit 4 packets. The first is not a retransmission. The remaining ones
        // have the increasing secs value.
        for i in 0..4 {
            let test_packet = TestBootpPacket::new()
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = &mut ReceivedPacket::new(&test_packet.get()).into_parsable();
            auditor.audit(packet);
        }
        // 60% of packets were retransmissions. The average secs field value was 1.2.
        auditor.receive_report(&mut report);
        assert_eq!(60.0, report.retransmit_percent);
        assert_eq!(1.2, report.retransmit_secs_avg);
        assert_eq!("2d:20:59:2b:0c:16", report.retransmit_longest_trying_client);
    }

    #[test]
    fn encode_to_prometheus() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        let mut registry = Registry::default();
        registry.register_collector(Box::new(analyzer.clone()));
        for i in 0..10 {
            let test_packet = TestBootpPacket::new();
            let test_packet = test_packet
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = ReceivedPacket::new(&test_packet.get());
            analyzer.audit_dhcpv4(&packet);
        }
        let mut buffer = String::new();
        encode(&mut buffer, &registry).unwrap();
        assert!(buffer.contains(
            "# HELP opcode_boot_requests_total Total number of the BootRequest messages."
        ));
        assert!(buffer
            .contains("# HELP opcode_boot_replies_total Total number of the BootReply messages."));
        assert!(buffer
            .contains("# HELP opcode_boot_replies_total Total number of the invalid messages."));
        assert!(buffer.contains(
            "# HELP opcode_boot_requests_percent Percentage of the BootRequest messages."
        ));
        assert!(buffer.contains("# TYPE opcode_boot_requests_percent gauge"));
        assert!(buffer.contains("opcode_boot_requests_percent 100.0"));
        assert!(buffer
            .contains("# HELP opcode_boot_replies_percent Percentage of the BootReply messages."));
        assert!(buffer.contains("# TYPE opcode_boot_replies_percent gauge"));
        assert!(buffer.contains("opcode_boot_replies_percent 0.0"));
        assert!(
            buffer.contains("# HELP opcode_invalid_percent Percentage of the invalid messages.")
        );
        assert!(buffer.contains("# TYPE opcode_invalid_percent gauge"));
        assert!(buffer.contains("opcode_invalid_percent 0.0"));
        assert!(buffer.contains("# HELP retransmit_percent Percentage of the retransmissions in the mssages sent by clients."));
        assert!(buffer.contains("# TYPE retransmit_percent gauge"));
        assert!(buffer.contains("retransmit_percent 90.0"));
        assert!(buffer.contains("# TYPE retransmit_secs_avg gauge"));
        assert!(buffer.contains("retransmit_secs_avg 4.5"));
        assert!(buffer.contains("# EOF"));
    }

    #[tokio::test]
    async fn http_encode_to_json() {
        let mut analyzer = Analyzer::new();
        analyzer.add_default_auditors();
        let result = analyzer.http_encode_to_json().await;
        assert!(result.is_ok());
        let body = to_bytes(result.unwrap().into_body()).await.unwrap();
        let body = body.as_str();
        assert_json!(body, { "opcode_boot_replies_percent": 0.0 });
    }
}
