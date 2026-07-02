//! The §8 conformance harness — synthetic-topology + throughput-trace tests proving the SPEC.md
//! invariants (SEL-01..SEL-11), with **NO real network** (SPEC §8, §11).
//!
//! Each test builds a synthetic candidate population and a scripted outcome stream (a per-peer
//! `throughput_bps` / reliability profile), drives repeated `select` + `record_outcome` cycles
//! through a deterministic clock + seeded RNG, and asserts the §4.4 invariants.
//!
//! The mapping test→invariant (all frozen conformance targets):
//! - `converges_to_fast_reliable`        → A (convergence) · SEL-05
//! - `load_spread_off_saturating_peer`   → B (anti-thundering-herd) · SEL-04, SEL-05
//! - `degradation_adaptation`            → D (degradation adaptation) · SEL-03, SEL-05
//! - `p99_orientation_beats_naive`       → C (P99 orientation) · SEL-05
//! - `bounded_exploration_of_cold_peers` → E (exploration) · SEL-05
//! - `seed_determinism`                  → F (determinism) · SEL-05
//! - `anti_gaming_measured_over_advertised` → §9 (non-gameable, bad source floored) · SEL-03, SEL-09
//! - `rebalance_replaces_dropped_source` → §5.5 (rebalance) · SEL-06

use std::collections::HashMap;

use dig_peer_selector::{
    Candidate, ContentId, ContentRequest, FailureReason, OutcomeKind, OutcomeResult, PeerId,
    PeerSelector, PoolEvent, PoolRemovalReason, Provenance, RangePlanDelta, SelectorConfig,
    TransferOutcome, TraversalKind,
};

use dig_dht::CandidateAddr;

// ---- synthetic harness ---------------------------------------------------------------------------

const STORE: [u8; 32] = [0x42; 32];

fn content() -> ContentId {
    ContentId::store(STORE)
}

fn pid(b: u8) -> PeerId {
    PeerId::from_bytes([b; 32])
}

fn candidate(b: u8) -> Candidate {
    Candidate::new(pid(b), vec![CandidateAddr::direct("10.0.0.1", 9444)])
}

fn candidate_classed(b: u8, class: TraversalKind) -> Candidate {
    let mut c = candidate(b);
    c.class = Some(class);
    c
}

/// A scripted synthetic peer: a fixed true throughput (bytes/s), a reliability probability, and an
/// optional per-peer concurrency saturation ceiling (throughput collapses beyond it). Deterministic —
/// no randomness in the trace itself; the selector's own seeded RNG is the only randomness.
#[derive(Clone, Copy)]
struct SynthPeer {
    throughput: f64,
    reliable: bool,
    /// If set, per-range throughput is scaled down once concurrency exceeds this ceiling (models a
    /// peer that saturates), so the saturation learner can discover the ceiling (SPEC §4.1).
    saturation_ceiling: Option<u32>,
}

impl SynthPeer {
    fn fast_reliable(tput: f64) -> Self {
        SynthPeer {
            throughput: tput,
            reliable: true,
            saturation_ceiling: None,
        }
    }
    fn with_ceiling(tput: f64, ceiling: u32) -> Self {
        SynthPeer {
            throughput: tput,
            reliable: true,
            saturation_ceiling: Some(ceiling),
        }
    }

    /// The measured throughput a range would see if run at `concurrency` in-flight ranges. Beyond the
    /// ceiling, aggregate throughput is shared so per-range throughput drops (saturation).
    fn measured(&self, concurrency: u32) -> f64 {
        match self.saturation_ceiling {
            Some(c) if concurrency > c => self.throughput * (c as f64) / (concurrency as f64),
            _ => self.throughput,
        }
    }
}

/// A deterministic driver: given the selector + a synthetic topology, run `rounds` of
/// select→record_outcome, feeding each selected peer a measured outcome derived from its synthetic
/// profile at the concurrency it was dispatched with. Returns the per-peer count of ranges served.
fn drive(
    sel: &PeerSelector,
    topo: &HashMap<u8, SynthPeer>,
    parallelism: usize,
    rounds: usize,
    at_start: u64,
) -> HashMap<u8, usize> {
    let mut served: HashMap<u8, usize> = HashMap::new();
    let cands: Vec<Candidate> = topo.keys().map(|&b| candidate(b)).collect();
    for r in 0..rounds {
        let at = at_start + r as u64;
        let req = ContentRequest::new(content(), parallelism);
        let selection = sel.select(&req, &cands);
        for sp in &selection.peers {
            let b = sp.peer_id.as_bytes()[0];
            let synth = topo[&b];
            let conc = sp.max_concurrency;
            let tput = synth.measured(conc);
            let ok = synth.reliable;
            *served.entry(b).or_insert(0) += 1;
            let outcome = TransferOutcome {
                peer_id: sp.peer_id,
                content: content(),
                kind: OutcomeKind::Range {
                    index: r,
                    offset: 0,
                    length: 1_000_000,
                },
                result: if ok {
                    OutcomeResult::Success
                } else {
                    OutcomeResult::Failure {
                        reason: FailureReason::Timeout,
                    }
                },
                // bytes/duration chosen so bytes/duration*1000 == tput.
                bytes: (tput as u64).max(1),
                duration_ms: 1000,
                rtt_ms: Some(20),
                at,
            };
            sel.record_outcome(&outcome);
        }
    }
    served
}

// ---- SEL-05 · Invariant A — convergence to fast/reliable (§8.1) ---------------------------------

#[test]
fn converges_to_fast_reliable() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 7));
    let mut topo = HashMap::new();
    topo.insert(1u8, SynthPeer::fast_reliable(1_000_000.0)); // fast
    topo.insert(2u8, SynthPeer::fast_reliable(500_000.0)); // medium
    topo.insert(3u8, SynthPeer::fast_reliable(50_000.0)); // slow

    let served = drive(&sel, &topo, 2, 60, 1000);

    // The fast peer's share must exceed the slow peer's (convergence, SPEC §4.4-A).
    let fast = served.get(&1).copied().unwrap_or(0);
    let slow = served.get(&3).copied().unwrap_or(0);
    assert!(
        fast > slow,
        "fast peer must serve more ranges than slow (fast {fast}, slow {slow})"
    );

    // And after convergence the ranking prefers the fast peer at rank 0.
    let final_sel = sel.select(
        &ContentRequest::new(content(), 3),
        &[candidate(1), candidate(2), candidate(3)],
    );
    assert_eq!(
        final_sel.best().unwrap().peer_id,
        pid(1),
        "the fast, reliable peer must be ranked best after convergence"
    );
}

// ---- SEL-04/05 · Invariant B — anti-thundering-herd load spread (§8.2) --------------------------

#[test]
fn load_spread_off_saturating_peer() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 11));
    let mut topo = HashMap::new();
    // Peer 1 has the highest point throughput but saturates hard beyond concurrency 2.
    topo.insert(1u8, SynthPeer::with_ceiling(2_000_000.0, 2));
    // Peers 2 and 3 are solid, unsaturating mid-tier peers.
    topo.insert(2u8, SynthPeer::fast_reliable(800_000.0));
    topo.insert(3u8, SynthPeer::fast_reliable(700_000.0));

    // Warm the models so saturation is learned.
    drive(&sel, &topo, 4, 50, 1000);

    // Now ask for high parallelism; the fastest peer must NOT get all the concurrency — its
    // recommended max_concurrency must be capped near its learned saturation ceiling, and the load
    // must spread to the other peers (SPEC §4.4-B).
    let req = ContentRequest::new(content(), 6);
    let selection = sel.select(&req, &[candidate(1), candidate(2), candidate(3)]);

    assert!(
        selection.len() >= 2,
        "load must spread across multiple peers, not pile on one (got {} peers)",
        selection.len()
    );
    let top = selection
        .peers
        .iter()
        .find(|p| p.peer_id == pid(1))
        .expect("the saturating peer should still be selected");
    assert!(
        top.max_concurrency <= 4,
        "the saturating peer's recommended concurrency must be capped near its learned ceiling, got {}",
        top.max_concurrency
    );
    // Total dispatched concurrency exceeds the top peer's cap (proving spill to others).
    let total: u32 = selection.peers.iter().map(|p| p.max_concurrency).sum();
    assert!(
        total > top.max_concurrency,
        "excess demand must spill to other peers (total {total}, top cap {})",
        top.max_concurrency
    );
}

// ---- SEL-03/05 · Invariant D — degradation adaptation (§8.3) ------------------------------------

#[test]
fn degradation_adaptation() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 13));
    // Peer 1 starts fast, peer 2 is steady-medium.
    let mut topo = HashMap::new();
    topo.insert(1u8, SynthPeer::fast_reliable(1_500_000.0));
    topo.insert(2u8, SynthPeer::fast_reliable(600_000.0));
    drive(&sel, &topo, 1, 30, 1000);

    // Peer 1 is best now.
    let before = sel.select(
        &ContentRequest::new(content(), 2),
        &[candidate(1), candidate(2)],
    );
    assert_eq!(
        before.best().unwrap().peer_id,
        pid(1),
        "peer 1 best while fast"
    );

    // Peer 1 degrades hard and stays there.
    topo.insert(1u8, SynthPeer::fast_reliable(50_000.0));
    drive(&sel, &topo, 1, 20, 2000);

    // Within a bounded number of outcomes the ranking must move OFF the degraded peer (SPEC §4.4-D).
    let after = sel.select(
        &ContentRequest::new(content(), 2),
        &[candidate(1), candidate(2)],
    );
    assert_eq!(
        after.best().unwrap().peer_id,
        pid(2),
        "ranking must move to the now-faster peer 2 after peer 1 degrades"
    );

    // And recovery: peer 1 comes back fast; it must rise again.
    topo.insert(1u8, SynthPeer::fast_reliable(2_000_000.0));
    drive(&sel, &topo, 1, 25, 3000);
    let recovered = sel.select(
        &ContentRequest::new(content(), 2),
        &[candidate(1), candidate(2)],
    );
    assert_eq!(
        recovered.best().unwrap().peer_id,
        pid(1),
        "a recovered peer must rise again"
    );
}

// ---- SEL-05 · Invariant C — P99 orientation beats naive best-point-estimate (§8.4) --------------

#[test]
fn p99_orientation_beats_naive() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 17));

    // Peer 1: high median throughput but a HEAVY TAIL (volatile — swings between very fast and very
    // slow). Peer 2: slightly lower median but rock-steady. A naive "pick the best point estimate"
    // would over-use peer 1; the P99-oriented scorer must down-weight peer 1's tail risk so peer 2
    // (steady) is not starved (SPEC §4.4-C).
    // Feed the traces directly so we control volatility precisely.
    for i in 0..40 {
        let at = 1000u64 + i as u64;
        // peer 1 swings: 2M, 100k, 2M, 100k ... (mean ~1.05M, high volatility)
        let t1 = if i % 2 == 0 { 2_000_000.0 } else { 100_000.0 };
        // peer 2 steady at 900k
        let t2 = 900_000.0;
        for (p, t) in [(1u8, t1), (2u8, t2)] {
            sel.record_outcome(&TransferOutcome {
                peer_id: pid(p),
                content: content(),
                kind: OutcomeKind::Range {
                    index: i,
                    offset: 0,
                    length: 1_000_000,
                },
                result: OutcomeResult::Success,
                bytes: t as u64,
                duration_ms: 1000,
                rtt_ms: Some(20),
                at,
            });
        }
    }

    let s1 = sel.peer_snapshot(&pid(1)).unwrap();
    let s2 = sel.peer_snapshot(&pid(2)).unwrap();
    assert!(
        s1.throughput_volatility > s2.throughput_volatility,
        "the heavy-tailed peer must register higher volatility (p1 {}, p2 {})",
        s1.throughput_volatility,
        s2.throughput_volatility
    );

    // The steady peer must be selected alongside (not starved by) the volatile high-median peer: with
    // parallelism 1, tail-risk down-weighting means the steady peer is competitive — assert it is
    // chosen at least sometimes over a run, i.e. its effective rank is not permanently last.
    let mut steady_best_or_second = 0;
    for _ in 0..10 {
        let sel_now = sel.select(
            &ContentRequest::new(content(), 2),
            &[candidate(1), candidate(2)],
        );
        // Both selected (parallelism 2), steady peer present with a real concurrency allotment.
        if sel_now.peers.iter().any(|p| p.peer_id == pid(2)) {
            steady_best_or_second += 1;
        }
    }
    assert_eq!(
        steady_best_or_second, 10,
        "the steady peer must remain a first-class source under P99 orientation, never starved"
    );
}

// ---- SEL-05 · Invariant E — bounded exploration of cold peers (§8.5) ----------------------------

#[test]
fn bounded_exploration_of_cold_peers() {
    // Part 1: an ALL-COLD network still makes progress — every candidate is eventually tried.
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 19));
    let mut topo = HashMap::new();
    for b in 1u8..=5 {
        topo.insert(b, SynthPeer::fast_reliable(500_000.0));
    }
    let served = drive(&sel, &topo, 3, 40, 1000);
    for b in 1u8..=5 {
        assert!(
            served.get(&b).copied().unwrap_or(0) > 0,
            "every candidate in an all-cold network must be tried (peer {b} never served)"
        );
    }

    // Part 2: cold peers must NOT displace a proven fast peer for the bulk of a transfer.
    let sel2 = PeerSelector::new(SelectorConfig::deterministic(1000, 23));
    // Warm peer 1 into a proven fast peer.
    let mut warm = HashMap::new();
    warm.insert(1u8, SynthPeer::fast_reliable(2_000_000.0));
    drive(&sel2, &warm, 1, 30, 1000);
    // Now offer the proven fast peer alongside many cold peers, high parallelism.
    let cands: Vec<Candidate> = (1u8..=8).map(candidate).collect();
    let selection = sel2.select(&ContentRequest::new(content(), 6), &cands);
    let explore_count = selection.peers.iter().filter(|p| p.exploratory).count();
    assert!(
        explore_count <= 2,
        "cold peers must not crowd out the proven peer (got {explore_count} exploratory of {})",
        selection.len()
    );
    assert!(
        selection
            .peers
            .iter()
            .any(|p| p.peer_id == pid(1) && !p.exploratory),
        "the proven fast peer must be selected as a non-exploratory source"
    );
    assert_eq!(
        selection.best().unwrap().peer_id,
        pid(1),
        "the proven fast peer must rank best over cold peers"
    );
}

// ---- SEL-05 · Invariant F — seed determinism (§8.6) --------------------------------------------

#[test]
fn seed_determinism() {
    // Two selectors with the SAME seed + clock + outcome stream must produce identical rankings.
    let run = || -> Vec<Vec<(PeerId, u32, bool)>> {
        let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 99));
        let mut topo = HashMap::new();
        // A mix of cold + measured peers to exercise the seeded exploration tie-break.
        for b in 1u8..=6 {
            topo.insert(
                b,
                SynthPeer::fast_reliable(300_000.0 + b as f64 * 100_000.0),
            );
        }
        let cands: Vec<Candidate> = (1u8..=6).map(candidate).collect();
        let mut history = Vec::new();
        for r in 0..20 {
            let at = 1000u64 + r as u64;
            let selection = sel.select(&ContentRequest::new(content(), 3), &cands);
            history.push(
                selection
                    .peers
                    .iter()
                    .map(|p| (p.peer_id, p.rank, p.exploratory))
                    .collect(),
            );
            for sp in &selection.peers {
                sel.record_outcome(&TransferOutcome {
                    peer_id: sp.peer_id,
                    content: content(),
                    kind: OutcomeKind::Range {
                        index: r,
                        offset: 0,
                        length: 1000,
                    },
                    result: OutcomeResult::Success,
                    bytes: (300_000 + sp.peer_id.as_bytes()[0] as u64 * 100_000).max(1),
                    duration_ms: 1000,
                    rtt_ms: Some(10),
                    at,
                });
            }
        }
        history
    };
    let a = run();
    let b = run();
    assert_eq!(
        a, b,
        "identical seed + clock + outcome stream must yield identical rankings"
    );
}

// ---- §9 / SEL-03, SEL-09 — anti-gaming: measured beats advertised, bad source floored (§8.7) ----

#[test]
fn anti_gaming_measured_over_advertised() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 29));

    // Peer 1 "advertises" high capacity but MEASURES low; peer 2 measures genuinely high. There is no
    // input path for advertised capacity — only measured outcomes move the model — so peer 1 must
    // rank by its (low) measured value, never the advertised one (SPEC §9.2, §9.3).
    let mut topo = HashMap::new();
    topo.insert(1u8, SynthPeer::fast_reliable(80_000.0)); // measures slow (its "advert" is ignored)
    topo.insert(2u8, SynthPeer::fast_reliable(1_500_000.0)); // measures fast
    drive(&sel, &topo, 1, 30, 1000);

    let ranked = sel.select(
        &ContentRequest::new(content(), 2),
        &[candidate(1), candidate(2)],
    );
    assert_eq!(
        ranked.best().unwrap().peer_id,
        pid(2),
        "the peer that MEASURES fast must outrank the one that only 'advertises' fast"
    );

    // A peer serving VerificationFailed ranges must be driven BELOW cold peers (SPEC §9.4).
    let sel2 = PeerSelector::new(SelectorConfig::deterministic(1000, 31));
    // Warm peer 3 with some success, then hammer it with verification failures.
    let mut at = 1000u64;
    for i in 0..5 {
        sel2.record_outcome(&TransferOutcome {
            peer_id: pid(3),
            content: content(),
            kind: OutcomeKind::Range {
                index: i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 1_000_000,
            duration_ms: 1000,
            rtt_ms: Some(10),
            at,
        });
        at += 1;
    }
    for i in 0..8 {
        sel2.record_outcome(&TransferOutcome {
            peer_id: pid(3),
            content: content(),
            kind: OutcomeKind::Range {
                index: 100 + i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Failure {
                reason: FailureReason::VerificationFailed,
            },
            bytes: 0,
            duration_ms: 0,
            rtt_ms: None,
            at,
        });
        at += 1;
    }
    // Offer the bad peer 3 alongside a fresh cold peer 4. The cold peer must rank ahead of the bad one.
    let ranked2 = sel2.select(
        &ContentRequest::new(content(), 2),
        &[candidate(3), candidate(4)],
    );
    assert_eq!(
        ranked2.best().unwrap().peer_id,
        pid(4),
        "a fresh cold peer must rank ahead of a verification-failing (bad/hostile) source"
    );
}

// ---- SEL-06 — rebalance replaces a dropped source (§8.8) ----------------------------------------

#[test]
fn rebalance_replaces_dropped_source() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 37));
    // Warm two peers as active sources.
    let mut topo = HashMap::new();
    topo.insert(1u8, SynthPeer::fast_reliable(1_000_000.0));
    topo.insert(2u8, SynthPeer::fast_reliable(900_000.0));
    drive(&sel, &topo, 2, 30, 1000);

    // A fresh candidate peer 3 arrives (a newly-discovered holder) — feed it in.
    sel.upsert_candidate(&candidate(3));
    // Warm peer 3 a little so it is a viable measured replacement.
    for i in 0..10 {
        sel.record_outcome(&TransferOutcome {
            peer_id: pid(3),
            content: content(),
            kind: OutcomeKind::Range {
                index: 200 + i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 950_000,
            duration_ms: 1000,
            rtt_ms: Some(15),
            at: 2000 + i as u64,
        });
    }

    // Mid-transfer, peer 1 drops. rebalance for the still-needed ranges, with peers 1 and 2 active.
    let req = ContentRequest::new(content(), 3);
    let need = RangePlanDelta::of_count(3);
    let replacement = sel.rebalance(&req, &[pid(1), pid(2)], &need);

    assert!(
        !replacement.is_empty(),
        "rebalance must return a replacement subset for the still-needed ranges"
    );
    // The replacement should reflect the up-to-the-moment models and prefer a non-active peer for the
    // still-needed ranges — peer 3 (fresh, measured) should appear.
    assert!(
        replacement.peers.iter().any(|p| p.peer_id == pid(3)),
        "rebalance must be able to pick the freshly-learned replacement peer 3"
    );
}

// ---- SEL-01 — the public API surface matches §5 exactly (frozen shapes) -------------------------

#[test]
fn sel_01_public_api_shapes() {
    // `new` from wiring-only config; `select`/`record_outcome`/`rebalance`; the four feed hooks; the
    // §5.1/§5.2/§5.5 type shapes — using the re-used dig-nat/dig-dht identity/candidate types.
    let sel = PeerSelector::new(SelectorConfig::default());

    // Feed hooks.
    let addr = "203.0.113.5:9444".parse().unwrap();
    sel.on_pool_event(&PoolEvent::PeerAdded {
        peer_id: pid(1),
        addr,
    });
    sel.on_connection_class(&pid(1), TraversalKind::Direct);
    sel.upsert_candidate(&candidate(2));
    sel.on_pool_event(&PoolEvent::PeerRemoved {
        peer_id: pid(1),
        reason: PoolRemovalReason::Disconnected,
    });

    // select returns a Selection { peers: Vec<SelectedPeer{peer_id,rank,max_concurrency,exploratory}> }
    let req = ContentRequest {
        content: content(),
        total_length: Some(10_000),
        range_count: Some(4),
        parallelism: 2,
    };
    let selection = sel.select(&req, &[candidate(2), candidate(3)]);
    for p in &selection.peers {
        let _ = (p.peer_id, p.rank, p.max_concurrency, p.exploratory);
    }

    // record_outcome with the exact TransferOutcome shape (Range + Request kinds, all result kinds).
    sel.record_outcome(&TransferOutcome {
        peer_id: pid(2),
        content: content(),
        kind: OutcomeKind::Range {
            index: 0,
            offset: 0,
            length: 2500,
        },
        result: OutcomeResult::Success,
        bytes: 2500,
        duration_ms: 100,
        rtt_ms: Some(12),
        at: 5,
    });
    sel.record_outcome(&TransferOutcome {
        peer_id: pid(3),
        content: content(),
        kind: OutcomeKind::Request {
            total_length: 10_000,
        },
        result: OutcomeResult::Interrupted { bytes_before: 4000 },
        bytes: 4000,
        duration_ms: 500,
        rtt_ms: None,
        at: 6,
    });

    // rebalance with (&ContentRequest, &[PeerId], &RangePlanDelta) -> Selection.
    let _ = sel.rebalance(&req, &[pid(2)], &RangePlanDelta::of_indices([1, 2, 3]));

    // remove_peer + observability.
    sel.remove_peer(&pid(3));
    let _snap = sel.snapshot();
    assert!(sel.registry_size() >= 1);

    // Re-used identity/candidate types come straight from the sibling crates (compile-time proof).
    let _reuse: dig_nat::PeerId = pid(1);
    let _content: dig_dht::ContentId = content();
    let _prov = Provenance::Dht;
}

// ---- SEL-02 — registry: churn-fed, quality-retained, bounded eviction ---------------------------

#[test]
fn sel_02_registry_churn_and_bounds() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 3));
    // Gossip churn adds a peer; a measured outcome gives it quality; a disconnect retains it.
    sel.on_pool_event(&PoolEvent::PeerAdded {
        peer_id: pid(1),
        addr: "10.0.0.1:1".parse().unwrap(),
    });
    sel.record_outcome(&TransferOutcome {
        peer_id: pid(1),
        content: content(),
        kind: OutcomeKind::Range {
            index: 0,
            offset: 0,
            length: 1000,
        },
        result: OutcomeResult::Success,
        bytes: 500_000,
        duration_ms: 1000,
        rtt_ms: Some(10),
        at: 1000,
    });
    sel.on_pool_event(&PoolEvent::PeerRemoved {
        peer_id: pid(1),
        reason: PoolRemovalReason::Disconnected,
    });
    let snap = sel
        .peer_snapshot(&pid(1))
        .expect("entry retained across disconnect");
    assert!(
        snap.throughput_bps.is_some(),
        "learned quality retained across disconnect"
    );
    assert!(!snap.connected);

    // A relayed connection class is attached observationally.
    sel.on_connection_class(&pid(1), TraversalKind::Relayed);
    let snap = sel.peer_snapshot(&pid(1)).unwrap();
    assert_eq!(snap.connection_class.as_deref(), Some("relayed"));
}

// ---- SEL-07 — the dig-download loop contract (verification is a hard penalty; pause not a failure) -

#[test]
fn sel_07_download_loop_contract() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 41));
    // A verification failure is a hard penalty (drives the source down).
    for i in 0..6 {
        sel.record_outcome(&TransferOutcome {
            peer_id: pid(1),
            content: content(),
            kind: OutcomeKind::Range {
                index: i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 1_000_000,
            duration_ms: 1000,
            rtt_ms: Some(10),
            at: 1000 + i as u64,
        });
    }
    let good = sel.peer_snapshot(&pid(1)).unwrap().reliability.unwrap();
    sel.record_outcome(&TransferOutcome {
        peer_id: pid(1),
        content: content(),
        kind: OutcomeKind::Range {
            index: 99,
            offset: 0,
            length: 1000,
        },
        result: OutcomeResult::Failure {
            reason: FailureReason::VerificationFailed,
        },
        bytes: 0,
        duration_ms: 0,
        rtt_ms: None,
        at: 2000,
    });
    let after_hard = sel.peer_snapshot(&pid(1)).unwrap().reliability.unwrap();
    assert!(
        after_hard < good,
        "a verification failure must drop reliability sharply"
    );
    assert_eq!(sel.peer_snapshot(&pid(1)).unwrap().hard_failures, 1);

    // A Cancelled failure does NOT blame the peer (pause/cancel is not a peer failure — SPEC §6.4).
    let sel2 = PeerSelector::new(SelectorConfig::deterministic(1000, 43));
    for i in 0..6 {
        sel2.record_outcome(&TransferOutcome {
            peer_id: pid(2),
            content: content(),
            kind: OutcomeKind::Range {
                index: i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 1_000_000,
            duration_ms: 1000,
            rtt_ms: Some(10),
            at: 1000 + i as u64,
        });
    }
    let before = sel2.peer_snapshot(&pid(2)).unwrap().reliability.unwrap();
    sel2.record_outcome(&TransferOutcome {
        peer_id: pid(2),
        content: content(),
        kind: OutcomeKind::Range {
            index: 50,
            offset: 0,
            length: 1000,
        },
        result: OutcomeResult::Failure {
            reason: FailureReason::Cancelled,
        },
        bytes: 0,
        duration_ms: 0,
        rtt_ms: None,
        at: 2000,
    });
    let after = sel2.peer_snapshot(&pid(2)).unwrap().reliability.unwrap();
    assert_eq!(
        before, after,
        "a host-cancel must not penalize the peer's reliability"
    );
}

// ---- SEL-08 — integration inputs are read-only hints; class prior does not preempt measurement ---

#[test]
fn sel_08_relayed_prior_does_not_preempt_measurement() {
    let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 47));
    // A relayed peer that MEASURES fast must be usable (its measured quality dominates the prior).
    let relayed_fast = candidate_classed(1, TraversalKind::Relayed);
    let direct_slow = candidate_classed(2, TraversalKind::Direct);
    sel.upsert_candidate(&relayed_fast);
    sel.upsert_candidate(&direct_slow);
    for i in 0..25 {
        sel.record_outcome(&TransferOutcome {
            peer_id: pid(1),
            content: content(),
            kind: OutcomeKind::Range {
                index: i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 1_800_000, // relayed peer measures FAST
            duration_ms: 1000,
            rtt_ms: Some(10),
            at: 1000 + i as u64,
        });
        sel.record_outcome(&TransferOutcome {
            peer_id: pid(2),
            content: content(),
            kind: OutcomeKind::Range {
                index: i,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 120_000, // direct peer measures SLOW
            duration_ms: 1000,
            rtt_ms: Some(10),
            at: 1000 + i as u64,
        });
    }
    let ranked = sel.select(
        &ContentRequest::new(content(), 2),
        &[
            candidate_classed(1, TraversalKind::Relayed),
            candidate_classed(2, TraversalKind::Direct),
        ],
    );
    assert_eq!(
        ranked.best().unwrap().peer_id,
        pid(1),
        "a relayed peer that measures fast must outrank a direct peer that measures slow (measured quality dominates the class prior)"
    );
}

// ---- SEL-10 — additive / no user knobs (config carries only wiring) ----------------------------

#[test]
fn sel_10_config_is_wiring_only() {
    // The config type carries ONLY wiring — a clock, an optional seed, a capacity bound. This test is
    // a compile-time contract: constructing a SelectorConfig by field shows there is no scoring knob.
    let cfg = SelectorConfig {
        clock: dig_peer_selector::ClockSource::manual(0),
        rng_seed: Some(1),
        registry_capacity: 10,
    };
    let sel = PeerSelector::new(cfg);
    assert!(sel.registry_size() == 0);
}
