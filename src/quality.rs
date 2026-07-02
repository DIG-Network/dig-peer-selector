//! [`PeerQuality`] — the per-peer, **measured-only** capacity/RTT/reliability model (SPEC.md §3).
//!
//! A peer's quality is refined EXCLUSIVELY from measured [`crate::TransferOutcome`]s (SPEC §3.1,
//! §9.2). There is deliberately no input path by which a peer raises its own score: observed capacity
//! always overrides advertised (SPEC §9.3). Every estimate here moves only when `record_outcome`
//! folds a real, executor-measured `(bytes, duration_ms)` into it.
//!
//! # The estimator and its normative properties (SPEC §3.2)
//!
//! Each of `throughput` and `rtt` is a recency-weighted [`Estimate`] over the peer's outcome stream.
//! The estimator is an EWMA whose smoothing factor is **derived from the peer's own observed
//! volatility** — there is NO baked policy decay constant (SPEC §3.2 P-volatility-tracking, §4.3):
//!
//! - **P-recency** — the newest sample always gets a non-trivial weight; older samples' influence
//!   decays geometrically.
//! - **P-monotone-convergence** — under a stationary stream (value `T` repeated) the estimate
//!   converges toward `T` and stays in a bounded neighborhood.
//! - **P-responsive-degradation** — when the true value shifts to `T_low` and stays, the estimate
//!   converges to `T_low` within a bounded number of samples (it does not stay pinned near `T_high`).
//! - **P-volatility-tracking** — the *effective memory* adapts to observed volatility: a steady peer
//!   is smoothed over a long window (small α); a swinging peer decays fast (large α) so a stale
//!   once-good reading falls off. Volatility is measured as the EWMA mean-absolute-deviation relative
//!   to the mean (a unitless coefficient of variation), so the decay is derived from the data.
//!
//! The estimator exposes a **confidence** (via `samples` and the observed relative volatility) so the
//! scorer can distinguish a well-measured peer from a barely-sampled one (SPEC §3.2, §4.4-E).

/// A recency-weighted estimate of a scalar quantity (throughput bytes/s, or RTT ms) with an
/// **adaptive, volatility-derived** smoothing factor — no baked decay constant (SPEC §3.2, §4.3).
///
/// Internally it tracks the EWMA mean and an EWMA of the absolute deviation (the volatility). The
/// smoothing factor `alpha` for the next update is a function of the *relative* volatility: steadier
/// streams get a smaller alpha (longer memory), volatile streams a larger alpha (faster decay). A
/// sample-count bootstrap makes early estimates converge quickly, satisfying P-recency + convergence
/// before enough history exists to measure volatility.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// The current recency-weighted mean. `None` until the first sample.
    mean: Option<f64>,
    /// EWMA of the absolute deviation from the mean — the observed volatility (same units as `mean`).
    mad: f64,
    /// Number of samples folded in.
    samples: u64,
}

impl Estimate {
    /// A fresh estimate with no samples.
    pub const fn new() -> Self {
        Estimate {
            mean: None,
            mad: 0.0,
            samples: 0,
        }
    }

    /// The current estimated value, or `None` if no sample has been folded in yet.
    pub fn value(&self) -> Option<f64> {
        self.mean
    }

    /// The number of samples folded in (a confidence signal).
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// The observed **relative volatility** (coefficient of variation): the EWMA absolute deviation
    /// divided by the mean. `0.0` for a steady peer, growing as outcomes swing. Used both to drive
    /// the adaptive decay (§4.3) and as a tail-risk signal for P99 orientation (§4.4-C).
    pub fn relative_volatility(&self) -> f64 {
        match self.mean {
            Some(m) if m.abs() > f64::EPSILON => (self.mad / m.abs()).clamp(0.0, 1.0),
            _ => 0.0,
        }
    }

    /// The adaptive smoothing factor for the *next* update — derived from sample count (bootstrap)
    /// and observed relative volatility (SPEC §3.2 P-volatility-tracking). No policy constant is
    /// exposed; the mapping is a fixed internal function of the data.
    ///
    /// - Bootstrap: with `n` prior samples the count-driven floor is `1/(n+1)` so the first samples
    ///   average in fully (fast early convergence, P-recency).
    /// - Volatility: a steady stream (relative volatility ~0) keeps alpha near the bootstrap floor
    ///   (long memory); a volatile stream lifts alpha toward a responsive ceiling so stale readings
    ///   fall off fast (P-responsive-degradation).
    fn next_alpha(&self) -> f64 {
        // Count bootstrap: 1/(n+1), so sample 1 => 1.0, sample 2 => 0.5, ... (classic running mean
        // for the cold phase). This guarantees P-monotone-convergence before volatility is known.
        let bootstrap = 1.0 / (self.samples as f64 + 1.0);
        // Volatility lift: interpolate between a steady floor and a responsive ceiling by the
        // observed relative volatility. These endpoints are estimator internals (not user knobs):
        //   steady   -> 0.15 (≈ 12-sample effective window: trust a consistent history)
        //   volatile -> 0.60 (≈ 2-3 sample window: a swinging peer's old readings are worthless)
        let vol = self.relative_volatility();
        let volatility_driven = 0.15 + (0.60 - 0.15) * vol;
        // Use the *larger* of the two so (a) the cold bootstrap dominates early and (b) once warm,
        // the volatility-derived rate takes over — never slower than the volatility says it should be.
        bootstrap.max(volatility_driven).clamp(0.0, 1.0)
    }

    /// Fold a measured `sample` into the estimate, updating the mean, the observed volatility, and the
    /// sample count. This is the ONLY way an estimate moves (measured-only, SPEC §3.1, §9.2).
    pub fn observe(&mut self, sample: f64) {
        match self.mean {
            None => {
                self.mean = Some(sample);
                self.mad = 0.0;
            }
            Some(prev) => {
                let alpha = self.next_alpha();
                let deviation = (sample - prev).abs();
                // Update volatility BEFORE the mean so alpha reflects volatility observed up to now;
                // the MAD uses the same adaptive alpha so it, too, tracks recent behavior.
                self.mad = (1.0 - alpha) * self.mad + alpha * deviation;
                self.mean = Some((1.0 - alpha) * prev + alpha * sample);
            }
        }
        self.samples = self.samples.saturating_add(1);
    }

    /// Seed a **prior** value without counting it as a measured sample (SPEC §3.3 connection-class
    /// prior). A prior is a starting point for a cold peer; the first real `observe` overrides it, so
    /// priors never cap a measured peer. `samples` stays 0 so the peer is still treated as cold for
    /// exploration purposes (SPEC §3.5).
    pub fn seed_prior(&mut self, value: f64) {
        if self.samples == 0 {
            self.mean = Some(value);
        }
    }
}

impl Default for Estimate {
    fn default() -> Self {
        Estimate::new()
    }
}

/// A recency-weighted reliability estimate in `[0, 1]` over `{success, failure}` outcomes (SPEC §3.4).
///
/// Satisfies P-recency and P-responsive-degradation: a peer that starts failing sees reliability
/// fall; a recovering peer sees it rise. A **hard** (verification) failure penalizes more sharply
/// than a soft transport failure (SPEC §3.4, §6.3) — it is folded in as multiple failure weights so a
/// bad/hostile source drops below cold peers (SPEC §9.4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reliability {
    /// The recency-weighted success rate. `None` until the first success/failure.
    rate: Option<f64>,
    /// Count of `{success, failure}` samples folded in.
    samples: u64,
    /// Count of hard (verification) failures observed — surfaced so the scorer can floor a bad source.
    hard_failures: u64,
}

impl Reliability {
    /// A fresh reliability estimate.
    pub const fn new() -> Self {
        Reliability {
            rate: None,
            samples: 0,
            hard_failures: 0,
        }
    }

    /// The current success probability in `[0,1]`, or `None` if unmeasured.
    pub fn rate(&self) -> Option<f64> {
        self.rate
    }

    /// Number of `{success, failure}` samples folded in.
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Number of hard (verification) failures observed (SPEC §9.4).
    pub fn hard_failures(&self) -> u64 {
        self.hard_failures
    }

    /// The recency-weighting alpha: a `1/(n+1)` bootstrap floored at a responsive minimum so a run of
    /// recent failures moves the rate promptly (P-responsive-degradation) rather than being diluted
    /// by a long success history.
    fn alpha(&self) -> f64 {
        (1.0 / (self.samples as f64 + 1.0)).max(0.25)
    }

    /// Fold a success (`ok = true`) or failure (`ok = false`) into the rate. A `hard` failure counts
    /// as several failure weights (SPEC §3.4) so a verification-failing source drops sharply.
    pub fn observe(&mut self, ok: bool, hard: bool) {
        let target = if ok { 1.0 } else { 0.0 };
        // A hard failure applies extra failure pressure: fold the 0.0 target multiple times.
        let repeats = if !ok && hard { 3 } else { 1 };
        for _ in 0..repeats {
            match self.rate {
                None => self.rate = Some(target),
                Some(prev) => {
                    let a = self.alpha();
                    self.rate = Some((1.0 - a) * prev + a * target);
                }
            }
            self.samples = self.samples.saturating_add(1);
        }
        if !ok && hard {
            self.hard_failures = self.hard_failures.saturating_add(1);
        }
    }

    /// Seed a **prior** reliability for a cold peer without counting it as measured (SPEC §3.3, §3.5).
    pub fn seed_prior(&mut self, value: f64) {
        if self.samples == 0 {
            self.rate = Some(value.clamp(0.0, 1.0));
        }
    }
}

impl Default for Reliability {
    fn default() -> Self {
        Reliability::new()
    }
}

/// The learned per-peer quality model (SPEC §3.1). Refined only from measured outcomes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeerQuality {
    /// Achievable throughput (bytes/sec), learned (SPEC §3.2).
    pub throughput: Estimate,
    /// Round-trip / time-to-first-byte latency (ms), learned (SPEC §3.2).
    pub rtt: Estimate,
    /// Success probability in `[0,1]`, learned (SPEC §3.4).
    pub reliability: Reliability,
    /// Count of measured outcomes folded in (confidence, SPEC §3.1).
    pub samples: u64,
    /// Ranges currently assigned to this peer (live in-flight, not learned — SPEC §3.1, §5.3).
    pub in_flight: u32,
}

impl PeerQuality {
    /// A cold quality model: no samples, unknown throughput/RTT/reliability (SPEC §3.5). Neither
    /// optimistic nor pessimistic — *uncertain*.
    pub const fn cold() -> Self {
        PeerQuality {
            throughput: Estimate::new(),
            rtt: Estimate::new(),
            reliability: Reliability::new(),
            samples: 0,
            in_flight: 0,
        }
    }

    /// Whether this peer is cold (no measured outcomes yet), qualifying for exploration (SPEC §3.5,
    /// §4.4-E).
    pub fn is_cold(&self) -> bool {
        self.samples == 0
    }

    /// A confidence weight in `[0,1]` — rises with samples, so a well-measured peer's point estimate
    /// is trusted more than a barely-sampled one (SPEC §3.2, §4.4-E). A saturating curve: a handful
    /// of samples already gives meaningful confidence, many samples approach full confidence.
    pub fn confidence(&self) -> f64 {
        let n = self.samples as f64;
        n / (n + 4.0)
    }

    /// Fold one measured throughput sample (bytes/sec) into the model.
    pub fn observe_throughput(&mut self, bps: f64) {
        self.throughput.observe(bps);
    }

    /// Fold one measured RTT sample (ms) into the model.
    pub fn observe_rtt(&mut self, ms: f64) {
        self.rtt.observe(ms);
    }

    /// Fold a success/failure into the reliability model (`hard` = a verification failure, SPEC §3.4).
    pub fn observe_result(&mut self, ok: bool, hard: bool) {
        self.reliability.observe(ok, hard);
    }

    /// Increment the count of measured outcomes (confidence).
    pub fn bump_samples(&mut self) {
        self.samples = self.samples.saturating_add(1);
    }
}

impl Default for PeerQuality {
    fn default() -> Self {
        PeerQuality::cold()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P-monotone-convergence: a stationary stream converges toward the true value and stays near it.
    #[test]
    fn estimate_converges_under_stationary_stream() {
        let mut e = Estimate::new();
        for _ in 0..50 {
            e.observe(1000.0);
        }
        let v = e.value().unwrap();
        assert!((v - 1000.0).abs() < 1.0, "converged to ~1000, got {v}");
        assert!(
            e.relative_volatility() < 0.01,
            "steady stream => low volatility"
        );
    }

    /// P-recency + P-responsive-degradation: after the true value drops, the estimate follows within a
    /// bounded number of samples and does NOT stay pinned near the old high.
    #[test]
    fn estimate_responds_to_degradation_within_bounded_samples() {
        let mut e = Estimate::new();
        for _ in 0..30 {
            e.observe(1000.0);
        }
        // Now the peer degrades to 100 and stays there.
        for _ in 0..15 {
            e.observe(100.0);
        }
        let v = e.value().unwrap();
        assert!(
            v < 300.0,
            "estimate must follow the drop toward 100 within a bounded window, got {v}"
        );
    }

    /// P-volatility-tracking: a volatile peer's estimate has a larger effective alpha (moves faster)
    /// than a steady peer's, so a swinging peer's stale readings fall off sooner.
    #[test]
    fn volatile_peer_decays_faster_than_steady_peer() {
        // Steady peer warmed to a stable mean.
        let mut steady = Estimate::new();
        for _ in 0..30 {
            steady.observe(500.0);
        }
        // Volatile peer swinging around a similar mean.
        let mut volatile = Estimate::new();
        for i in 0..30 {
            volatile.observe(if i % 2 == 0 { 100.0 } else { 900.0 });
        }
        assert!(
            volatile.relative_volatility() > steady.relative_volatility(),
            "swinging stream must register higher volatility"
        );
        // Both now receive the same big new reading; the volatile one must move MORE toward it.
        let steady_before = steady.value().unwrap();
        let volatile_before = volatile.value().unwrap();
        steady.observe(2000.0);
        volatile.observe(2000.0);
        let steady_move = steady.value().unwrap() - steady_before;
        let volatile_move = volatile.value().unwrap() - volatile_before;
        assert!(
            volatile_move > steady_move,
            "volatile peer must react more to a new reading (adaptive decay): steady {steady_move}, volatile {volatile_move}"
        );
    }

    #[test]
    fn prior_is_overridden_by_first_measurement() {
        let mut e = Estimate::new();
        e.seed_prior(50.0);
        assert_eq!(e.value(), Some(50.0));
        assert_eq!(e.samples(), 0, "a prior is not a measured sample");
        e.observe(1000.0);
        assert_eq!(
            e.value(),
            Some(1000.0),
            "first measurement overrides the prior"
        );
        assert_eq!(e.samples(), 1);
    }

    #[test]
    fn reliability_falls_on_failure_and_rises_on_recovery() {
        let mut r = Reliability::new();
        for _ in 0..10 {
            r.observe(true, false);
        }
        assert!(r.rate().unwrap() > 0.9);
        for _ in 0..10 {
            r.observe(false, false);
        }
        assert!(
            r.rate().unwrap() < 0.3,
            "reliability must fall on a failure run"
        );
        for _ in 0..10 {
            r.observe(true, false);
        }
        assert!(r.rate().unwrap() > 0.7, "reliability must recover");
    }

    #[test]
    fn hard_failure_penalizes_more_than_soft_failure() {
        let mut soft = Reliability::new();
        let mut hard = Reliability::new();
        for _ in 0..5 {
            soft.observe(true, false);
            hard.observe(true, false);
        }
        soft.observe(false, false);
        hard.observe(false, true);
        assert!(
            hard.rate().unwrap() < soft.rate().unwrap(),
            "a hard (verification) failure must drop reliability more than a soft one"
        );
        assert_eq!(hard.hard_failures(), 1);
    }

    #[test]
    fn cold_quality_is_uncertain_and_confidence_grows() {
        let mut q = PeerQuality::cold();
        assert!(q.is_cold());
        assert_eq!(q.confidence(), 0.0);
        for _ in 0..4 {
            q.observe_throughput(500.0);
            q.bump_samples();
        }
        assert!(!q.is_cold());
        assert!(
            (q.confidence() - 0.5).abs() < 1e-9,
            "4 samples => 4/(4+4)=0.5"
        );
    }
}
