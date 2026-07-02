//! The autonomous scoring function (SPEC.md §4): learned saturation per class, an adaptive relayed
//! penalty, volatility-driven decay (in [`crate::quality`]), the min-P99 + anti-thundering-herd
//! objective, and the ranked-subset output — satisfying invariants A–G (SPEC §4.4).
//!
//! # What is learned here (no baked constants, no user knobs — SPEC §1.5, §4)
//!
//! - **Saturation point per peer class** ([`SaturationModel`], SPEC §4.1). From the observed relation
//!   between a peer's `in_flight` at dispatch and the throughput the resulting outcomes measured, the
//!   model learns the concurrency beyond which a class's per-range throughput stops rising. A new peer
//!   of a known class inherits the class prior, then specializes.
//! - **Adaptive relayed penalty** ([`RelayModel`], SPEC §4.2). Learned from the *measured* throughput
//!   of relayed vs non-relayed transfers — it shrinks where relayed links measure nearly as well as
//!   direct and grows where they measure much worse. Subordinate to per-peer measured quality.
//! - **Volatility-driven decay** — lives in the [`crate::quality::Estimate`] (its alpha is derived
//!   from observed volatility, SPEC §3.2/§4.3); the scorer reads the resulting estimate + its
//!   volatility as a tail-risk signal.
//!
//! # The objective (SPEC §4.4)
//!
//! Jointly **minimize P99 request latency** (make the slowest ranges faster, not just the median) and
//! **avoid thundering-herd** collapse on a fast peer. The scorer produces a per-peer *effective score*
//! that (a) rewards measured throughput × reliability, (b) is discounted for tail risk (volatility,
//! low reliability, near-saturation), (c) is penalized for a relayed path by the learned amount, and
//! (d) floors a verification-failing (bad/hostile) source below cold peers. It then dispatches by
//! filling each peer only up to its learned saturation headroom (anti-herd) and spilling to the next.

use dig_nat::TraversalKind;

use crate::quality::PeerQuality;
use crate::registry::PeerEntry;

/// A coarse **peer class** — the equivalence bucket the selector learns saturation behavior *per*
/// (SPEC §1.3, §4.1). NOT the raw connection class: peers reached by a similar path share a
/// saturation prior, so a new peer of a known class inherits a sane concurrency prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerClass {
    /// A direct peer-to-peer data path (Direct / mapped / hole-punched — the relay carries no bytes).
    DirectPath,
    /// A relayed path — the relay carries every byte (SPEC §1.3 relay-last invariant).
    RelayedPath,
    /// Class unknown (no connection class observed yet).
    Unknown,
}

impl PeerClass {
    /// The coarse class for a `dig-nat` connection class (SPEC §4.1). Every non-relayed tier is a
    /// peer-to-peer data path; only `Relayed` means the relay carries the bytes.
    pub fn of(class: Option<TraversalKind>) -> Self {
        match class {
            Some(TraversalKind::Relayed) => PeerClass::RelayedPath,
            Some(_) => PeerClass::DirectPath,
            None => PeerClass::Unknown,
        }
    }

    /// Whether this is a relayed path (attracts the learned relayed penalty, SPEC §4.2).
    pub fn is_relayed(self) -> bool {
        matches!(self, PeerClass::RelayedPath)
    }
}

/// The learned saturation model per [`PeerClass`] (SPEC §4.1). Tracks, per class, the concurrency at
/// which measured per-range throughput stops rising — so the scorer caps a peer's concurrent ranges
/// at its learned headroom and spreads the excess (anti-thundering-herd, SPEC §4.4-B).
#[derive(Debug, Clone)]
pub struct SaturationModel {
    /// Per-class learned saturation point (max useful concurrent ranges). Learned, adapts (SPEC §4.1).
    direct: SaturationEstimate,
    relayed: SaturationEstimate,
    unknown: SaturationEstimate,
}

impl Default for SaturationModel {
    fn default() -> Self {
        SaturationModel {
            // Class priors: a fresh, unmeasured class starts with a modest concurrency so a peer is
            // tried with a little parallelism, then the point is learned from measured outcomes.
            // These are ESTIMATOR SEEDS (learned away by data), not user knobs.
            direct: SaturationEstimate::seeded(4.0),
            relayed: SaturationEstimate::seeded(2.0),
            unknown: SaturationEstimate::seeded(3.0),
        }
    }
}

impl SaturationModel {
    fn slot(&self, class: PeerClass) -> &SaturationEstimate {
        match class {
            PeerClass::DirectPath => &self.direct,
            PeerClass::RelayedPath => &self.relayed,
            PeerClass::Unknown => &self.unknown,
        }
    }

    fn slot_mut(&mut self, class: PeerClass) -> &mut SaturationEstimate {
        match class {
            PeerClass::DirectPath => &mut self.direct,
            PeerClass::RelayedPath => &mut self.relayed,
            PeerClass::Unknown => &mut self.unknown,
        }
    }

    /// The learned saturation point (max useful concurrent ranges) for a class — always `>= 1`.
    pub fn saturation_point(&self, class: PeerClass) -> u32 {
        self.slot(class).point()
    }

    /// Fold an observation: at dispatch a peer of `class` had `in_flight_at_dispatch` ranges in
    /// flight and the resulting transfer measured `throughput_bps`. The model raises the class's
    /// saturation point when more concurrency still yields throughput, and lowers it when higher
    /// concurrency coincides with degraded per-range throughput (SPEC §4.1).
    pub fn observe(&mut self, class: PeerClass, in_flight_at_dispatch: u32, throughput_bps: f64) {
        self.slot_mut(class)
            .observe(in_flight_at_dispatch, throughput_bps);
    }
}

/// Per-class saturation estimator: learns the concurrency at which per-range throughput peaks.
///
/// It keeps the best `(concurrency, throughput)` seen and, when a *higher* concurrency measures a
/// clearly-lower per-range throughput, concludes saturation sits at the lower concurrency; when a
/// higher concurrency still improves throughput, it lifts the point. The point drifts (EWMA) so it
/// adapts if the class's capacity changes (SPEC §4.1 "must adapt").
#[derive(Debug, Clone)]
struct SaturationEstimate {
    /// The current learned saturation point (fractional; exposed rounded, `>= 1`).
    point: f64,
    /// The best per-range throughput seen so far (for detecting a degradation with more concurrency).
    best_throughput: f64,
    /// The concurrency at which `best_throughput` was seen.
    best_concurrency: f64,
    samples: u64,
}

impl SaturationEstimate {
    fn seeded(point: f64) -> Self {
        SaturationEstimate {
            point,
            best_throughput: 0.0,
            best_concurrency: 1.0,
            samples: 0,
        }
    }

    fn point(&self) -> u32 {
        (self.point.round() as i64).max(1) as u32
    }

    fn observe(&mut self, in_flight_at_dispatch: u32, throughput_bps: f64) {
        let conc = (in_flight_at_dispatch.max(1)) as f64;
        self.samples = self.samples.saturating_add(1);
        if throughput_bps <= 0.0 {
            return;
        }
        // Adaptive learning rate: converge fast early, then drift slowly (adapts to capacity change).
        let alpha = (1.0 / (self.samples as f64)).max(0.1);
        if throughput_bps >= self.best_throughput {
            // Better throughput at this concurrency: raise the point toward this concurrency (there
            // is still headroom), and remember the new best.
            self.best_throughput = throughput_bps;
            self.best_concurrency = conc;
            let target = conc.max(self.point);
            self.point = (1.0 - alpha) * self.point + alpha * target;
        } else if conc > self.best_concurrency && throughput_bps < 0.8 * self.best_throughput {
            // More concurrency but clearly-worse throughput => past saturation: pull the point back
            // toward the best-known concurrency (SPEC §4.1 degrade-on-oversubscription).
            let target = self.best_concurrency;
            self.point = (1.0 - alpha) * self.point + alpha * target;
        }
        // Keep the point sane.
        self.point = self.point.clamp(1.0, 64.0);
    }
}

/// The learned, adaptive relayed penalty (SPEC §4.2). A multiplicative factor in `(0, 1]` applied to a
/// relayed peer's score, learned from how relayed transfers *measure* against non-relayed ones — it
/// shrinks toward 1.0 when relayed links measure nearly as well, grows (toward a floor) when they
/// measure much worse. Subordinate to per-peer measured quality: a relayed peer that measures fast is
/// barely penalized; a relayed peer that measures slow is de-prioritized by both its own low estimate
/// AND this factor.
#[derive(Debug, Clone, Default)]
pub struct RelayModel {
    /// EWMA mean measured throughput of relayed transfers.
    relayed_mean: Option<f64>,
    /// EWMA mean measured throughput of non-relayed transfers.
    direct_mean: Option<f64>,
    relayed_samples: u64,
    direct_samples: u64,
}

impl RelayModel {
    /// Fold one measured transfer into the relay model, tagged by whether its path was relayed.
    pub fn observe(&mut self, relayed: bool, throughput_bps: f64) {
        if throughput_bps <= 0.0 {
            return;
        }
        if relayed {
            self.relayed_samples += 1;
            let a = (1.0 / self.relayed_samples as f64).max(0.1);
            self.relayed_mean = Some(match self.relayed_mean {
                None => throughput_bps,
                Some(m) => (1.0 - a) * m + a * throughput_bps,
            });
        } else {
            self.direct_samples += 1;
            let a = (1.0 / self.direct_samples as f64).max(0.1);
            self.direct_mean = Some(match self.direct_mean {
                None => throughput_bps,
                Some(m) => (1.0 - a) * m + a * throughput_bps,
            });
        }
    }

    /// The current learned relayed-penalty factor in `[floor, 1.0]`. `1.0` = no penalty (relayed
    /// measures as well as direct or better); smaller = relayed measures worse. Before enough data on
    /// both sides, returns a mild default penalty (relayed links *often* cost more — SPEC §4.2) that
    /// is quickly replaced by the measured ratio.
    pub fn penalty(&self) -> f64 {
        const FLOOR: f64 = 0.25; // never zero out a relayed peer purely on the class prior.
        match (self.relayed_mean, self.direct_mean) {
            (Some(r), Some(d)) if d > 0.0 => (r / d).clamp(FLOOR, 1.0),
            // Insufficient paired data: a mild prior penalty, learned away once both sides measure.
            _ => 0.85,
        }
    }
}

/// A per-peer scored candidate: the effective score + the concurrency headroom + whether it is a cold
/// exploratory pick. The engine ranks by `effective_score` (desc) and dispatches by `headroom`.
#[derive(Debug, Clone, Copy)]
pub struct ScoredPeer {
    /// The peer's registry index-free identity is carried by the engine; here we hold the score parts.
    /// The higher, the better (SPEC §4.4-A).
    pub effective_score: f64,
    /// The recommended concurrent-range headroom for this peer (its learned saturation point minus
    /// its current in-flight, `>= 0`; a selected peer gets `>= 1`). Anti-herd (SPEC §4.4-B, §4.5).
    pub headroom: u32,
    /// Whether this is a cold exploratory pick (SPEC §4.4-E).
    pub exploratory: bool,
    /// A stable tie-break salt (derived from the peer id) so equal scores order deterministically
    /// (SPEC §4.4-F) unless the engine's seeded RNG chooses among cold peers.
    pub tie_break: u64,
}

/// Compute a peer's **effective score** and its exploratory flag against the learned models
/// (SPEC §4.4). Higher score = preferred. This is a pure function of the entry's measured quality +
/// the learned saturation/relay models — no self-reported input can raise it (SPEC §9.2).
///
/// The score encodes the joint objective:
/// - base value = measured throughput × reliability (convergence to fast/reliable, SPEC §4.4-A);
/// - a **tail-risk discount** for volatility, low reliability, and near-saturation (P99 orientation,
///   SPEC §4.4-C) — a peer likely to leave a range straggling is down-weighted for the tail;
/// - a **learned relayed penalty** for a relayed path (SPEC §4.2);
/// - a **hard floor** for a verification-failing source: driven below any cold peer (SPEC §9.4);
/// - a **cold exploration bonus** bounded so cold peers get tried but do not crowd out proven fast
///   peers (SPEC §4.4-E).
pub fn score_peer(
    entry: &PeerEntry,
    saturation: &SaturationModel,
    relay: &RelayModel,
    exploration_bonus: f64,
) -> ScoredPeer {
    let q = &entry.quality;
    let class = PeerClass::of(entry.connection_class);
    let sat_point = saturation.saturation_point(class);
    let headroom = sat_point.saturating_sub(q.in_flight);
    let tie_break = tie_break_salt(entry);

    // --- Cold peer: exploratory, scored just above the worst proven peer so it gets tried but does
    //     not displace a measured fast peer for the bulk of a transfer (SPEC §4.4-E, §3.5).
    if q.is_cold() {
        return ScoredPeer {
            effective_score: exploration_bonus,
            headroom: headroom.max(1),
            exploratory: true,
            tie_break,
        };
    }

    // --- Hard-source floor: a verification-failing peer is worse than an unknown one (SPEC §9.4).
    if is_bad_source(q) {
        return ScoredPeer {
            effective_score: -1.0e12 + tie_break as f64 * 1e-6,
            headroom: headroom.max(1),
            exploratory: false,
            tie_break,
        };
    }

    let tput = q.throughput.value().unwrap_or(0.0);
    let rel = q.reliability.rate().unwrap_or(0.5);
    let conf = q.confidence();

    // Base value: measured throughput weighted by reliability. Observed capacity only (SPEC §9.3).
    let base = tput * rel;

    // Tail-risk discount (P99 orientation, SPEC §4.4-C): volatility (unpredictable tail), unreliability
    // (straggle/refetch risk), and near-saturation (queuing tail) each shave the score. A high-median
    // but heavy-tailed peer is down-weighted for tail-sensitive assignment.
    let volatility = q.throughput.relative_volatility();
    let saturation_pressure = if sat_point == 0 {
        1.0
    } else {
        (q.in_flight as f64 / sat_point as f64).clamp(0.0, 1.0)
    };
    let tail_discount =
        (1.0 - 0.5 * volatility) * (0.5 + 0.5 * rel) * (1.0 - 0.4 * saturation_pressure);

    // Confidence blends the measured value toward a neutral baseline for barely-sampled peers, so a
    // single lucky sample does not vault an under-measured peer above a well-measured one (SPEC §3.2).
    let confident_value = base * (0.3 + 0.7 * conf);

    // Learned relayed penalty (SPEC §4.2), subordinate to the measured value above.
    let relay_factor = if class.is_relayed() {
        relay.penalty()
    } else {
        1.0
    };

    let effective_score = confident_value * tail_discount * relay_factor;

    ScoredPeer {
        effective_score,
        headroom,
        exploratory: false,
        tie_break,
    }
}

/// Whether a peer is a bad/hostile source that must sink below cold peers (SPEC §9.4): it has served
/// verification-failing ranges AND its measured reliability is poor.
fn is_bad_source(q: &PeerQuality) -> bool {
    q.reliability.hard_failures() > 0 && q.reliability.rate().unwrap_or(1.0) < 0.5
}

/// A stable per-peer tie-break salt derived from the `peer_id` bytes — deterministic ordering for
/// equal scores (SPEC §4.4-F) without needing entropy.
fn tie_break_salt(entry: &PeerEntry) -> u64 {
    let b = entry.peer_id.as_bytes();
    let mut acc = 0u64;
    for &x in b.iter().take(8) {
        acc = (acc << 8) | x as u64;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Provenance;
    use dig_nat::PeerId;

    fn entry(b: u8) -> PeerEntry {
        PeerEntry::cold(PeerId::from_bytes([b; 32]), Provenance::Dht, 0)
    }

    #[test]
    fn peer_class_maps_relayed_vs_direct() {
        assert_eq!(
            PeerClass::of(Some(TraversalKind::Relayed)),
            PeerClass::RelayedPath
        );
        assert_eq!(
            PeerClass::of(Some(TraversalKind::Direct)),
            PeerClass::DirectPath
        );
        assert_eq!(
            PeerClass::of(Some(TraversalKind::HolePunch)),
            PeerClass::DirectPath
        );
        assert_eq!(PeerClass::of(None), PeerClass::Unknown);
    }

    #[test]
    fn faster_reliable_peer_scores_higher() {
        let sat = SaturationModel::default();
        let relay = RelayModel::default();

        let mut fast = entry(1);
        for _ in 0..10 {
            fast.quality.observe_throughput(1000.0);
            fast.quality.observe_result(true, false);
            fast.quality.bump_samples();
        }
        let mut slow = entry(2);
        for _ in 0..10 {
            slow.quality.observe_throughput(100.0);
            slow.quality.observe_result(true, false);
            slow.quality.bump_samples();
        }
        let sf = score_peer(&fast, &sat, &relay, 0.0);
        let ss = score_peer(&slow, &sat, &relay, 0.0);
        assert!(sf.effective_score > ss.effective_score);
    }

    #[test]
    fn cold_peer_is_exploratory_and_bounded() {
        let sat = SaturationModel::default();
        let relay = RelayModel::default();
        let cold = entry(1);
        let s = score_peer(&cold, &sat, &relay, 50.0);
        assert!(s.exploratory);
        assert_eq!(s.effective_score, 50.0);
        assert!(s.headroom >= 1);
    }

    #[test]
    fn bad_source_sinks_below_cold_peers() {
        let sat = SaturationModel::default();
        let relay = RelayModel::default();
        let mut bad = entry(1);
        // Warm it, then hammer verification failures.
        for _ in 0..5 {
            bad.quality.observe_throughput(1000.0);
            bad.quality.observe_result(true, false);
            bad.quality.bump_samples();
        }
        for _ in 0..8 {
            bad.quality.observe_result(false, true);
            bad.quality.bump_samples();
        }
        let sbad = score_peer(&bad, &sat, &relay, 0.0);
        let cold = entry(2);
        let scold = score_peer(&cold, &sat, &relay, 10.0);
        assert!(
            sbad.effective_score < scold.effective_score,
            "a verification-failing source must rank below a cold peer"
        );
    }

    #[test]
    fn saturation_model_lowers_point_on_oversubscription_degradation() {
        let mut m = SaturationModel::default();
        // At concurrency 2, great throughput.
        for _ in 0..5 {
            m.observe(PeerClass::DirectPath, 2, 1000.0);
        }
        let p_before = m.saturation_point(PeerClass::DirectPath);
        // At higher concurrency 8, throughput collapses => saturation is below 8.
        for _ in 0..8 {
            m.observe(PeerClass::DirectPath, 8, 200.0);
        }
        let p_after = m.saturation_point(PeerClass::DirectPath);
        assert!(
            p_after <= p_before,
            "oversubscription with degraded throughput must not raise the saturation point (before {p_before}, after {p_after})"
        );
        assert!(p_after >= 1);
    }

    #[test]
    fn relay_penalty_shrinks_when_relayed_measures_as_well_as_direct() {
        let mut m = RelayModel::default();
        for _ in 0..10 {
            m.observe(false, 1000.0);
            m.observe(true, 950.0);
        }
        assert!(
            m.penalty() > 0.9,
            "near-parity relayed links => small penalty"
        );

        let mut m2 = RelayModel::default();
        for _ in 0..10 {
            m2.observe(false, 1000.0);
            m2.observe(true, 300.0);
        }
        assert!(
            m2.penalty() < 0.5,
            "much-worse relayed links => large penalty"
        );
    }
}
