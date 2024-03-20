//! `analyzer` is a module containing the packet analysis and reporting logic.

use std::sync::Mutex;
use std::{fmt::Debug, sync::Arc};

use endure_lib::listener::{self, PacketWrapper};
use endure_lib::metric::FromMetricsStore;
use endure_lib::metric::{InitMetrics, Metric, MetricValue, MetricsStore, SharedMetricsStore};
use endure_macros::{cond_add_auditor, AuditProfileCheck, FromMetricsStore};

use crate::proto::{bootp::OpCode, dhcp::v4};

use actix_web::HttpResponse;
use prometheus_client::collector::Collector;

use simple_moving_average::*;

const METRIC_OPCODE_BOOT_REQUESTS_COUNT: &str = "opcode_boot_requests_count";
const METRIC_OPCODE_BOOT_REPLIES_COUNT: &str = "opcode_boot_replies_count";
const METRIC_OPCODE_INVALID_COUNT: &str = "opcode_invalid_count";
const METRIC_OPCODE_BOOT_REQUESTS_PERCENT: &str = "opcode_boot_requests_percent";
const METRIC_OPCODE_BOOT_REPLIES_PERCENT: &str = "opcode_boot_replies_percent";
const METRIC_OPCODE_INVALID_PERCENT: &str = "opcode_invalid_percent";
const METRIC_RETRANSMIT_PERCENT: &str = "retransmit_percent";
const METRIC_RETRANSMIT_SECS_AVG: &str = "retransmit_secs_avg";
const METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT: &str = "retransmit_longest_trying_client";

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

/// Capture and analysis profiles.
#[derive(PartialEq)]
pub enum AuditProfile {
    /// All auditors enabled and online capture.
    LiveStreamAll,
    /// All auditors enabled and pcap analysis.
    PcapAll,
}

/// A trait that must be implemented by each DHCPv4 auditor.
///
/// The [`Analyzer`] calls the [`DHCPv4PacketAuditor::audit`] function
/// for each received BOOTP packet. The auditor runs specialized
/// checks on the packet and updates its local state and maintained
/// metrics. The [`Analyzer`] can call [`DHCPv4PacketAuditor::collect_metrics`]
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

    /// Collects metrics from the auditor in the metrics store.
    ///
    /// This function is called by the [`Analyzer`] for each auditor. The
    /// auditor writes its metrics into the metrics store.
    ///
    fn collect_metrics(&mut self);
}

/// A trait implemented by the auditors checking if they should be executed
/// for the specified [`AuditProfile`].
pub trait AuditProfileCheck {
    /// Checks if the auditor should be run for the specified profile.
    fn has_audit_profile(audit_profile: &AuditProfile) -> bool;
}

/// A central instance receiving the captured packets and performing their
/// analysis using available auditors.
///
/// It recognizes received packet types and selects appropriate auditors
/// to perform the analysis.
///
/// # Installing an auditor
///
/// Auditors installed in the [`Analyzer`] must belong to one or more
/// profiles (see [`AuditProfile`]). If the user specifies the profile in
/// the configuration the [`Analyzer`] selects only the auditors matching
/// this profile. Therefore, each auditor must be annotated with the
/// profiles it belongs to using the [`AuditProfileCheck`] macro and
/// the `profile` attribute. The auditors must also derive the
/// [`FromMetricsStore`] trait implementation, so they can be instantiated
/// in the [`Analyzer::add_dhcpv4_auditors`], or other function installing
/// the auditors. Finally, the auditors must be conditionally installed in
/// [`Analyzer::add_dhcpv4_auditors`] or other similar function appropriate
/// for the auditor type.
#[derive(Clone, Debug)]
pub struct Analyzer {
    auditors: Arc<Mutex<AnalyzerAuditorsState>>,
    metrics_store: SharedMetricsStore,
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
            metrics_store: MetricsStore::new().with_timestamp().to_shared(),
        }
    }

    /// Installs auditors for the specified [`AuditProfile`].
    ///
    /// # Parameters
    ///
    /// - `audit_profile` - auditors belonging to this profile will be enabled.
    ///
    pub fn add_dhcpv4_auditors(&mut self, audit_profile: &AuditProfile) {
        let auditors = &mut self.auditors.lock().unwrap().dhcpv4_auditors;
        cond_add_auditor!(RetransmissionAuditor);
        cond_add_auditor!(OpCodeAuditor);
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
        }
    }

    /// Collects and teturns the current metrics from all DHCPv4 auditors.
    ///
    /// # Usage
    ///
    /// Typically, this function is called periodically to make the metrics
    /// available to an external reader (e.g., to append the metrics as a
    /// row of a CSV file or to a Prometheus exporter).
    ///
    pub fn current_dhcpv4_metrics(&self) -> SharedMetricsStore {
        for auditor in self.auditors.lock().unwrap().dhcpv4_auditors.iter_mut() {
            auditor.collect_metrics();
        }
        self.metrics_store.clone()
    }

    /// Returns current metrics in an HTTP response.
    ///
    /// This function is called directly from the HTTP server handler returning
    /// the metrics as a JSON string.
    ///
    /// # Errors
    ///
    /// This function returns no errors.
    pub async fn http_encode_to_json(&self) -> actix_web::Result<HttpResponse> {
        let mut writer = String::new();
        let result = self
            .metrics_store
            .read()
            .unwrap()
            .serialize_json(&mut writer);
        if result.is_err() {
            return Ok(HttpResponse::InternalServerError()
                .content_type("application/json")
                .finish());
        }
        Ok(HttpResponse::Ok()
            .content_type("application/json")
            .body(writer))
    }
}

impl Collector for Analyzer {
    fn encode(
        &self,
        encoder: prometheus_client::encoding::DescriptorEncoder,
    ) -> Result<(), std::fmt::Error> {
        self.current_dhcpv4_metrics()
            .read()
            .unwrap()
            .encode(encoder)
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
///
#[derive(AuditProfileCheck, Clone, Debug, FromMetricsStore)]
#[profiles(AuditProfile::LiveStreamAll, AuditProfile::PcapAll)]
pub struct OpCodeAuditor {
    metrics_store: SharedMetricsStore,
    requests_count: i64,
    replies_count: i64,
    invalid_count: i64,
    opcodes: PercentSMA<3, 100>,
}

impl Default for OpCodeAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            requests_count: Default::default(),
            replies_count: Default::default(),
            invalid_count: Default::default(),
            opcodes: PercentSMA::new(),
        }
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

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_COUNT,
            MetricValue::Int64Value(self.requests_count),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_COUNT,
            MetricValue::Int64Value(self.replies_count),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_COUNT,
            MetricValue::Int64Value(self.invalid_count),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(0)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(1)),
        );

        metrics_store.set_metric_value(
            METRIC_OPCODE_INVALID_PERCENT,
            MetricValue::Float64Value(self.opcodes.average(2)),
        );
    }
}

impl InitMetrics for OpCodeAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REQUESTS_COUNT,
            "Total number of the BootRequest messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REPLIES_COUNT,
            "Total number of the BootReply messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_INVALID_COUNT,
            "Total number of the invalid messages.",
            MetricValue::Int64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT,
            "Percentage of the BootRequest messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_BOOT_REPLIES_PERCENT,
            "Percentage of the BootReply messages.",
            MetricValue::Float64Value(Default::default()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_OPCODE_INVALID_PERCENT,
            "Percentage of the invalid messages.",
            MetricValue::Float64Value(Default::default()),
        ));
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
///
#[derive(AuditProfileCheck, Debug, FromMetricsStore)]
#[profiles(AuditProfile::LiveStreamAll, AuditProfile::PcapAll)]
pub struct RetransmissionAuditor {
    metrics_store: SharedMetricsStore,
    retransmits: RoundedSMA<10, 100>,
    secs: RoundedSMA<10, 100>,
    longest_trying_client: MovingRanks<String, u16, 1, 100>,
}

impl Default for RetransmissionAuditor {
    fn default() -> Self {
        Self {
            metrics_store: Default::default(),
            retransmits: RoundedSMA::new(),
            secs: RoundedSMA::new(),
            longest_trying_client: MovingRanks::new(),
        }
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

    fn collect_metrics(&mut self) {
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_PERCENT,
            "Percentage of the retransmissions in the mssages sent by clients.",
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_SECS_AVG,
            "Average retransmission time (i.e. average time in retransmissions to acquire a new lease).",
            MetricValue::Float64Value(self.secs.average()),
        ));
        if let Some(longest_trying_client) = self.longest_trying_client.get_rank(0) {
            metrics_store.set_metric(Metric::new(
                METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
                "MAC address of the the client who has been trying the longest to acquire a lease.",
                MetricValue::StringValue(longest_trying_client.id.clone()),
            ));
        }
    }
}

impl InitMetrics for RetransmissionAuditor {
    fn init_metrics(&mut self, metrics_store: &SharedMetricsStore) {
        self.metrics_store = metrics_store.clone();
        let mut metrics_store = self.metrics_store.write().unwrap();
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_PERCENT,
            "Percentage of the retransmissions in the mssages sent by clients.",
            MetricValue::Float64Value(self.retransmits.average()),
        ));

        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_SECS_AVG,
            "Average retransmission time (i.e. average time in retransmissions to acquire a new lease).",
            MetricValue::Float64Value(self.secs.average()),
        ));
        metrics_store.set_metric(Metric::new(
            METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
            "MAC address of the the client who has been trying the longest to acquire a lease.",
            MetricValue::StringValue("".to_string()),
        ));
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::{AuditProfile, AuditProfileCheck, DHCPv4PacketAuditor, FromMetricsStore};
    use actix_web::{body::to_bytes, web::Bytes};
    use assert_json::assert_json;
    use pcap::{Linktype, PacketHeader};
    use prometheus_client::{encoding::text::encode, registry::Registry};

    use super::{Analyzer, MovingRanks, OpCodeAuditor, RoundedSMA};
    use crate::{
        analyzer::{
            RetransmissionAuditor, METRIC_OPCODE_BOOT_REPLIES_COUNT,
            METRIC_OPCODE_BOOT_REPLIES_PERCENT, METRIC_OPCODE_BOOT_REQUESTS_COUNT,
            METRIC_OPCODE_BOOT_REQUESTS_PERCENT, METRIC_OPCODE_INVALID_COUNT,
            METRIC_OPCODE_INVALID_PERCENT, METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT,
            METRIC_RETRANSMIT_PERCENT, METRIC_RETRANSMIT_SECS_AVG,
        },
        proto::{bootp::*, dhcp::v4::ReceivedPacket, tests::common::TestBootpPacket},
    };
    use endure_lib::{
        listener::{self, PacketWrapper},
        metric::MetricsStore,
    };

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
    fn moving_ranks() {
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
    fn rounded_sma_prec10() {
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
    fn rounded_sma_prec100() {
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
    fn rounded_sma_window_size() {
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
    fn analyzer_receive_dhcp4_packet_ethernet() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
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

        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        let metric = metric.unwrap().get_value::<f64>();
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(100.0, metric);
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_loopback() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
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

        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        let metric = metric.unwrap().get_value::<f64>();
        assert!(metric.is_some());
        let metric = metric.unwrap();
        assert_eq!(100.0, metric);
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_non_matching_filter() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
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

        // The packet shouldn't be analyzed and the metrics should not
        // be updated.
        let metrics_store = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics_store.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        assert_eq!(0.0, metric.unwrap().get_value_unwrapped::<f64>())
    }

    #[test]
    fn analyzer_receive_dhcp4_packet_truncated() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
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

        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();
        let metric = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(metric.is_some());
        assert_eq!(0.0, metric.unwrap().get_value_unwrapped::<f64>())
    }

    #[test]
    fn analyzer_audit_dhcpv4() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
        for i in 0..10 {
            let test_packet = TestBootpPacket::new();
            let test_packet = test_packet
                .set(OPCODE_POS, &vec![1])
                .set(SECS_POS, &vec![0, i]);
            let packet = ReceivedPacket::new(&test_packet.get());
            analyzer.audit_dhcpv4(&packet);
        }
        let metrics = analyzer.current_dhcpv4_metrics().read().unwrap().clone();

        let opcode_boot_replies_percent = metrics.get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            0.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_requests_percent = metrics.get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            100.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics.get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_percent = metrics.get(METRIC_RETRANSMIT_PERCENT);
        assert!(retransmit_percent.is_some());
        assert_eq!(
            90.0,
            retransmit_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_secs_avg = metrics.get(METRIC_RETRANSMIT_SECS_AVG);
        assert!(retransmit_secs_avg.is_some());
        assert_eq!(
            4.5,
            retransmit_secs_avg.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_longest_trying_client = metrics.get(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT);
        assert!(retransmit_longest_trying_client.is_some());
        assert_eq!(
            "2d:20:59:2b:0c:16",
            retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
        );
    }

    #[test]
    fn opcode_auditor_profiles() {
        assert!(OpCodeAuditor::has_audit_profile(
            &AuditProfile::LiveStreamAll
        ));
        assert!(OpCodeAuditor::has_audit_profile(&AuditProfile::PcapAll));
    }

    #[test]
    fn opcode_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = OpCodeAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet.set(OPCODE_POS, &vec![1]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        // Audit 5 request packets. They should constitute 100% of all packets.
        for _ in 0..5 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();
        let metrics_store_ref = metrics_store.clone();

        let opcode_boot_requests_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_COUNT);
        assert!(opcode_boot_requests_count.is_some());
        assert_eq!(
            5,
            opcode_boot_requests_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_boot_replies_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_COUNT);
        assert!(opcode_boot_replies_count.is_some());
        assert_eq!(
            0,
            opcode_boot_replies_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_invalid_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_COUNT);
        assert!(opcode_invalid_count.is_some());
        assert_eq!(
            0,
            opcode_invalid_count.unwrap().get_value_unwrapped::<i64>()
        );

        let opcode_boot_requests_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            100.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_replies_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            0.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        // Audit 3 reply packets. Now we have 8 packets audited (62.5% are requests and 37.5%
        // are replies).
        let test_packet = test_packet.set(OPCODE_POS, &vec![2]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..3 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        let opcode_boot_requests_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_COUNT);
        assert!(opcode_boot_requests_count.is_some());
        assert_eq!(
            5,
            opcode_boot_requests_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_boot_replies_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_COUNT);
        assert!(opcode_boot_replies_count.is_some());
        assert_eq!(
            3,
            opcode_boot_replies_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_invalid_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_COUNT);
        assert!(opcode_invalid_count.is_some());
        assert_eq!(
            0,
            opcode_invalid_count.unwrap().get_value_unwrapped::<i64>()
        );

        let opcode_boot_requests_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            62.5,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_replies_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            37.5,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            0.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );

        // Finally, let's add some 2 invalid packets with opcode 3. We have a total of 10 packets
        // (50% of requests, 30% of replies and 20% invalid).
        let test_packet = test_packet.set(OPCODE_POS, &vec![3]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();
        for _ in 0..2 {
            auditor.audit(packet);
        }
        auditor.collect_metrics();

        let opcode_boot_requests_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_COUNT);
        assert!(opcode_boot_requests_count.is_some());
        assert_eq!(
            5,
            opcode_boot_requests_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_boot_replies_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_COUNT);
        assert!(opcode_boot_replies_count.is_some());
        assert_eq!(
            3,
            opcode_boot_replies_count
                .unwrap()
                .get_value_unwrapped::<i64>()
        );

        let opcode_invalid_count = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_COUNT);
        assert!(opcode_invalid_count.is_some());
        assert_eq!(
            2,
            opcode_invalid_count.unwrap().get_value_unwrapped::<i64>()
        );

        let opcode_boot_requests_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REQUESTS_PERCENT);
        assert!(opcode_boot_requests_percent.is_some());
        assert_eq!(
            50.0,
            opcode_boot_requests_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_boot_replies_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_BOOT_REPLIES_PERCENT);
        assert!(opcode_boot_replies_percent.is_some());
        assert_eq!(
            30.0,
            opcode_boot_replies_percent
                .unwrap()
                .get_value_unwrapped::<f64>()
        );

        let opcode_invalid_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_OPCODE_INVALID_PERCENT);
        assert!(opcode_invalid_percent.is_some());
        assert_eq!(
            20.0,
            opcode_invalid_percent.unwrap().get_value_unwrapped::<f64>()
        );
    }

    #[test]
    fn retransmissions_auditor_profiles() {
        assert!(RetransmissionAuditor::has_audit_profile(
            &AuditProfile::LiveStreamAll
        ));
        assert!(RetransmissionAuditor::has_audit_profile(
            &AuditProfile::PcapAll
        ));
    }

    #[test]
    fn retransmissions_auditor_audit() {
        let metrics_store = MetricsStore::new().to_shared();
        let mut auditor = RetransmissionAuditor::from_metrics_store(&metrics_store);
        let test_packet = TestBootpPacket::new();
        let test_packet = test_packet
            .set(OPCODE_POS, &vec![1])
            .set(SECS_POS, &vec![0, 0]);
        let packet = &mut ReceivedPacket::new(test_packet.get()).into_parsable();

        // Audit the packet having secs field value of 0. It doesn't count as retransmission.
        auditor.audit(packet);
        auditor.collect_metrics();

        let metrics_store_ref = metrics_store.clone();

        let retransmit_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_PERCENT);
        assert!(retransmit_percent.is_some());
        assert_eq!(
            0.0,
            retransmit_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_secs_avg = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_SECS_AVG);
        assert!(retransmit_secs_avg.is_some());
        assert_eq!(
            0.0,
            retransmit_secs_avg.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_longest_trying_client = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT);
        assert!(retransmit_longest_trying_client.is_some());
        assert_eq!(
            "",
            retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
        );

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
        auditor.collect_metrics();

        let retransmit_percent = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_PERCENT);
        assert!(retransmit_percent.is_some());
        assert_eq!(
            60.0,
            retransmit_percent.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_secs_avg = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_SECS_AVG);
        assert!(retransmit_secs_avg.is_some());
        assert_eq!(
            1.2,
            retransmit_secs_avg.unwrap().get_value_unwrapped::<f64>()
        );

        let retransmit_longest_trying_client = metrics_store_ref
            .read()
            .unwrap()
            .get(METRIC_RETRANSMIT_LONGEST_TRYING_CLIENT);
        assert!(retransmit_longest_trying_client.is_some());
        assert_eq!(
            "2d:20:59:2b:0c:16",
            retransmit_longest_trying_client
                .unwrap()
                .get_value_unwrapped::<String>()
        );
    }

    #[test]
    fn encode_to_prometheus() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
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
            "# HELP opcode_boot_requests_count Total number of the BootRequest messages."
        ));
        assert!(buffer
            .contains("# HELP opcode_boot_replies_count Total number of the BootReply messages."));
        assert!(
            buffer.contains("# HELP opcode_invalid_count Total number of the invalid messages.")
        );
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
    async fn analyzer_http_encode_to_json() {
        let mut analyzer = Analyzer::new();
        analyzer.add_dhcpv4_auditors(&AuditProfile::LiveStreamAll);
        let result = analyzer.http_encode_to_json().await;
        assert!(result.is_ok());
        let body = to_bytes(result.unwrap().into_body()).await.unwrap();
        let body = body.as_str();
        assert_json!(body, { METRIC_OPCODE_BOOT_REPLIES_PERCENT: 0.0 });
    }
}
