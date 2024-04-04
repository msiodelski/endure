//! `util` is a module containing tools for auditors to calculate metrics.

use simple_moving_average::{NoSumSMA, SMA};

/// A single record held in the [`MovingRanks`] container.
///
/// It contains an identifier, score and the age of the given rank.
///
/// # Generic Parameters
///
/// - `Indent` - a unique rank identifier. It typically associates the rank
///   with a client (e.g., MAC address).
/// - `Score` - a score that can be compared with other ranks. It is a metric
///   associated with  a client (e.g., `secs` field value).
///
#[derive(Debug)]
pub struct MovingRank<Indent, Score>
where
    Score: std::cmp::PartialOrd,
{
    /// A rank identifier.
    ///
    /// Typically a string value, such as client MAC address.
    pub id: Indent,

    /// A metric used for scoring.
    ///
    /// Typically a number that can be compared with other numbers (ranks).
    /// The higher number is scored as a higher rank.
    pub score: Score,

    /// Score age.
    ///
    /// There is a limit in the [`MovingRanks`] how long the ranks are held.
    /// That's why an age of each rank has to be increased when a new score
    /// is reported. Newer scores eventually replace the older scores when
    /// their lifetime expires.
    pub age: usize,
}

impl<Indent, Score> MovingRank<Indent, Score>
where
    Indent: std::cmp::PartialEq,
    Score: std::cmp::PartialOrd,
{
    /// Instantiates a new rank with an age of 0.
    ///
    /// # Parameters
    ///
    /// - `id` - rank identifier.
    /// - `score` - score to be ranked.
    pub fn new(id: Indent, score: Score) -> MovingRank<Indent, Score> {
        MovingRank { id, score, age: 0 }
    }
}

/// Tracks and holds the highest metrics associated with different clients.
///
/// # Generic Parameters
///
/// - `Indent` - a unique rank identifier. It typically associates the rank
///   with a client (e.g., MAC address).
/// - `Score` - a score that can be compared with other ranks. It is a metric
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
///
#[derive(Debug)]
pub struct MovingRanks<Indent, Score, const RANKS_NUM: usize, const WINDOW_SIZE: usize>
where
    Indent: std::cmp::PartialEq,
    Score: std::cmp::PartialOrd,
{
    /// Stored ranks.
    ///
    /// This vector has a length between 0 and `RANKS_NUM`. The ranks can be
    /// retrieved using the [`MovingRanks::get_rank`] function.
    ranks: Vec<MovingRank<Indent, Score>>,
}

impl<Indent, Score, const RANKS_NUM: usize, const WINDOW_SIZE: usize>
    MovingRanks<Indent, Score, RANKS_NUM, WINDOW_SIZE>
where
    Indent: std::cmp::PartialEq,
    Score: std::cmp::PartialOrd,
{
    /// Instantiates the [`MovingRanks`].
    ///
    /// It creates an empty set of ranks.
    pub fn new() -> MovingRanks<Indent, Score, RANKS_NUM, WINDOW_SIZE> {
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
    ///
    pub fn add_score(&mut self, id: Indent, score: Score) {
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
    ///
    pub fn get_rank(&self, index: usize) -> Option<&MovingRank<Indent, Score>> {
        self.ranks.get(index)
    }
}

/// Collection of related counters with calculable percentages for each
/// counter.
///
/// A typical application of the [`TotalCounter`] is when an auditor counts
/// several types of the processed messages and needs to calculate occurrence
/// percentage of each message type among all messages.
///
/// # Generic Parameters
///
/// - `COUNTERS_NUM` - a number of different `u64` counters.
///
/// # Usage Example
///
/// Suppose you want to track the occurrence of 3 message types. The [`TotalCounter`]
/// can be used as follows to display the percentages for each counter:
///
/// ```rust
/// let mut totals = TotalCounter::<3>::new();
/// totals.increase(0);
/// totals.increase(1);
/// println!("{}", totals.percentage(0)); // should print 50.0
/// println!("{}", totals.percentage(1)); // should print 50.0
/// println!("{}", totals.percentage(2)); // should print 0.0
/// ```
///
/// It is also possible to get the absolute values using the [`TotalCounter::counter`]
/// function.
///
#[derive(Clone, Debug)]
pub struct TotalCounter<const COUNTERS_NUM: usize> {
    counters: [i64; COUNTERS_NUM],
}

impl<const METRICS_NUM: usize> TotalCounter<METRICS_NUM> {
    /// Instantiates the counters.
    pub fn new() -> Self {
        TotalCounter {
            counters: [0; METRICS_NUM],
        }
    }

    /// Increases a selected counter by `1`.
    ///
    /// # Errors
    ///
    /// This function will panic if the `metric_index` is out of bounds.
    ///
    pub fn increase(&mut self, metric_index: usize) {
        // Add a sample of `1` to a selected metric.
        self.counters[metric_index] += 1;
    }

    /// Returns the current value for a selected counter.
    ///
    /// # Errors
    ///
    /// This function will panic if the `metric_index` is out of bounds.
    ///
    pub fn counter(&self, metric_index: usize) -> i64 {
        self.counters[metric_index]
    }

    /// Returns the percentage of the selected metrics value among all values.
    ///
    /// # Errors
    ///
    /// This function will panic if the `metric_index` is out of bounds.
    ///
    pub fn percentage(&self, metric_index: usize) -> f64 {
        let mut sum: i64 = 0;
        for i in 0..METRICS_NUM {
            sum += self.counters[i];
        }
        match sum {
            0 => 0.0,
            sum => (1000 * self.counters[metric_index] / sum) as f64 / 10f64,
        }
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
pub struct PercentSMA<const METRICS_NUM: usize, const WINDOW_SIZE: usize> {
    averages: [NoSumSMA<u64, u64, WINDOW_SIZE>; METRICS_NUM],
}

impl<const METRICS_NUM: usize, const WINDOW_SIZE: usize> PercentSMA<METRICS_NUM, WINDOW_SIZE> {
    /// Instantiates the [`PercentSMA`].
    pub fn new() -> PercentSMA<METRICS_NUM, WINDOW_SIZE> {
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
    pub fn increase(&mut self, metric_index: usize) {
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
    pub fn average(self, metric_index: usize) -> f64 {
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
pub struct RoundedSMA<const PRECISION: usize, const WINDOW_SIZE: usize> {
    sma: NoSumSMA<u64, u64, WINDOW_SIZE>,
}

impl<const PRECISION: usize, const WINDOW_SIZE: usize> RoundedSMA<PRECISION, WINDOW_SIZE> {
    /// Instantiates the [`RoundedSMA`].
    pub fn new() -> RoundedSMA<PRECISION, WINDOW_SIZE> {
        RoundedSMA {
            sma: NoSumSMA::new(),
        }
    }

    /// Adds a sample.
    ///
    /// # Parameters
    ///
    /// - sample - a sample value.
    pub fn add_sample(&mut self, sample: u64) {
        self.sma.add_sample(PRECISION as u64 * sample);
    }

    /// Returns an average with a selected precision.
    pub fn average(self) -> f64 {
        self.sma.get_average() as f64 / PRECISION as f64
    }
}

/// A total average implementation with an arbitrary precision.
///
/// It has the same interface as the [`RoundedSMA`] but it calculates an
/// average value from all samples rather than from a moving window of
/// samples. It uses less memory than [`RoundedSMA`] because it doesn't need
/// to retain the samples. It only retains the total value and the number
/// of samples.
///
/// # Generic Parameters
///
/// - PRECISION - selected precision (i.e., 10 for single decimal, 100 for two decimals
///   1000 for three, etc.)
///
#[derive(Debug)]
pub struct RoundedSTA<const PRECISION: usize> {
    sum: u64,
    samples_num: u64,
}

impl<const PRECISION: usize> RoundedSTA<PRECISION> {
    /// Instantiates the [`RoundedSMA`].
    pub fn new() -> RoundedSTA<PRECISION> {
        RoundedSTA {
            sum: 0,
            samples_num: 0,
        }
    }

    /// Adds a sample.
    ///
    /// # Parameters
    ///
    /// - sample - a sample value.
    pub fn add_sample(&mut self, sample: u64) {
        self.sum += PRECISION as u64 * sample;
        self.samples_num += 1;
    }

    /// Returns an average with a selected precision.
    pub fn average(&self) -> f64 {
        match self.samples_num {
            0 => 0.0,
            _ => (self.sum / self.samples_num) as f64 / PRECISION as f64,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::auditor::util::{RoundedSMA, RoundedSTA};

    use super::{MovingRanks, TotalCounter};

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
    fn total_counter_zero() {
        let totals = TotalCounter::<3>::new();
        assert_eq!(0.0, totals.percentage(0));
        assert_eq!(0.0, totals.percentage(1));
        assert_eq!(0.0, totals.percentage(2));

        assert_eq!(0, totals.counter(0));
        assert_eq!(0, totals.counter(1));
        assert_eq!(0, totals.counter(2));
    }

    #[test]
    fn total_counter() {
        let mut totals = TotalCounter::<3>::new();
        for _ in 0..3 {
            totals.increase(0);
        }
        for _ in 0..4 {
            totals.increase(1);
        }
        assert_eq!(42.8, totals.percentage(0));
        assert_eq!(57.1, totals.percentage(1));
        assert_eq!(0.0, totals.percentage(2));

        assert_eq!(3, totals.counter(0));
        assert_eq!(4, totals.counter(1));
        assert_eq!(0, totals.counter(2));
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
    fn rounded_sta_prec10() {
        let mut avg = RoundedSTA::<10>::new();
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
    fn rounded_sta_prec100() {
        let mut avg = RoundedSTA::<100>::new();
        avg.add_sample(1);
        assert_eq!(1.0, avg.average());
        avg.add_sample(0);
        assert_eq!(0.5, avg.average());
        avg.add_sample(1);
        assert_eq!(0.66, avg.average());
        avg.add_sample(8);
        assert_eq!(2.5, avg.average());
    }
}
