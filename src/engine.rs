//! [`PeerSelector`] — the public engine (SPEC.md §5): the closed `select → record_outcome →
//! rebalance` decision + learning loop over the registry (§2), the measured-only quality model (§3),
//! and the autonomous scorer (§4).
//!
//! The selector is pure + in-memory: `select`/`rebalance` never block on I/O, and `record_outcome`
//! folds a measured result into the models in real time so the next decision is smarter (SPEC §5).
//! Interior mutability ([`std::sync::Mutex`]) lets the hooks take `&self` (SPEC §5.1) while the engine
//! mutates the registry + learned models.

use std::sync::Mutex;

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;

use dig_nat::{PeerId, TraversalKind};

use crate::config::SelectorConfig;
use crate::observe::{PeerSnapshot, SelectorSnapshot};
use crate::pool_event::{PoolEvent, PoolRemovalReason};
use crate::quality::PeerQuality;
use crate::registry::Registry;
use crate::scoring::{score_peer, PeerClass, RelayModel, SaturationModel, ScoredPeer};
use crate::types::{
    Candidate, ContentRequest, OutcomeKind, OutcomeResult, Provenance, RangePlanDelta,
    SelectedPeer, Selection, TransferOutcome,
};

/// The learned + live state behind the engine's interior mutability.
struct Inner {
    registry: Registry,
    saturation: SaturationModel,
    relay: RelayModel,
    rng: Pcg64Mcg,
    /// Records, per dispatched range, the `(peer, in_flight_at_dispatch, class)` so a later outcome
    /// can attribute the saturation observation to the concurrency the range actually ran under
    /// (SPEC §4.1). Keyed by `(peer_id, range_index)`.
    dispatched: std::collections::HashMap<(PeerId, usize), DispatchRecord>,
    /// A monotonically-increasing `select`/`rebalance` counter — the "epoch" used to round-robin
    /// exploration coverage so no eligible peer is starved (SPEC §4.4-E: every candidate is tried,
    /// even at parallelism 1; SPEC §4.4-D: a degraded-then-recovered peer is re-probed).
    epoch: u64,
    /// The last epoch each peer appeared in a selection — drives the anti-starvation re-exploration:
    /// the most-starved eligible peer (largest `epoch - last_selected`, cold peers having `0`) is
    /// guaranteed a periodic turn so it acquires fresh outcomes.
    last_selected: std::collections::HashMap<PeerId, u64>,
}

impl Inner {
    /// Prune `last_selected` + `dispatched` for every `peer_id` the registry has just reported as
    /// evicted/removed (#179 finding 2). MUST be called after every registry-mutating operation that
    /// can shed an entry (capacity eviction on upsert/mark-connected/set-class, or explicit removal) so
    /// neither side map ever retains a key for a peer no longer in the registry. Cheap when nothing was
    /// evicted (the common case): `drain_evicted` returns an empty `Vec`.
    fn prune_evicted_side_maps(&mut self) {
        for peer in self.registry.drain_evicted() {
            self.last_selected.remove(&peer);
            self.dispatched.retain(|(id, _), _| *id != peer);
        }
    }
}

/// What a dispatched range recorded at dispatch time, for saturation learning (SPEC §4.1).
#[derive(Clone, Copy)]
struct DispatchRecord {
    in_flight_at_dispatch: u32,
    class: PeerClass,
}

/// The self-optimizing peer selector (SPEC §5, §11). Construct with [`PeerSelector::new`], feed it
/// registry churn + DHT candidates, ask it to [`select`](PeerSelector::select) a source subset, and
/// stream every measured outcome back via [`record_outcome`](PeerSelector::record_outcome).
pub struct PeerSelector {
    config: SelectorConfig,
    inner: Mutex<Inner>,
}

impl PeerSelector {
    /// Construct a selector from wiring-only [`SelectorConfig`] (SPEC §5.6). No behavior knobs — every
    /// tradeoff is learned.
    pub fn new(config: SelectorConfig) -> Self {
        let rng = Pcg64Mcg::seed_from_u64(config.effective_seed());
        let registry = Registry::new(config.registry_capacity);
        PeerSelector {
            config,
            inner: Mutex::new(Inner {
                registry,
                saturation: SaturationModel::default(),
                relay: RelayModel::default(),
                rng,
                dispatched: std::collections::HashMap::new(),
                epoch: 0,
                last_selected: std::collections::HashMap::new(),
            }),
        }
    }

    /// The current time from the injected clock (SPEC §5.6).
    fn now(&self) -> u64 {
        self.config.clock.now()
    }

    /// **`select`** — rank a candidate set for a request (SPEC §5.1).
    ///
    /// Registers any fresh candidate (cold — its first pick is exploratory, SPEC §2.3, §4.4-E),
    /// scores every eligible candidate against the learned models, and returns a ranked chosen subset
    /// bounded by the request's parallelism. Each chosen peer carries its recommended `max_concurrency`
    /// (its learned saturation headroom, SPEC §4.1/§4.5) and its `exploratory` flag. Anti-herd: total
    /// dispatched concurrency is filled peer-by-peer up to each peer's headroom, spilling to the next
    /// (SPEC §4.4-B). Dispatch bumps in-flight so the very next `select`/`rebalance` sees it.
    pub fn select(&self, req: &ContentRequest, candidates: &[Candidate]) -> Selection {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        // Register fresh candidates (cold) — selecting a candidate registers it (SPEC §2.3).
        for c in candidates {
            inner.registry.upsert_candidate(c, Provenance::Dht, now);
        }
        // A fresh upsert may have evicted an over-capacity entry (§2.5) — prune its side-map residue
        // before scoring (#179 finding 2).
        inner.prune_evicted_side_maps();
        self.select_over(&mut inner, req, &candidate_ids(candidates), &[], now)
    }

    /// **`rebalance`** — re-query the up-to-the-moment models for still-needed ranges (SPEC §5.5).
    ///
    /// Mid-transfer, when a source drops or a range must be relocated, the executor calls this to get
    /// a replacement subset for the `need`ed ranges, de-ranking the already-`active` peers (they are
    /// counted as busy so their headroom shrinks) and reflecting every `record_outcome` received so
    /// far. It obeys the same invariants as `select` (SPEC §4.4).
    pub fn rebalance(
        &self,
        req: &ContentRequest,
        active: &[PeerId],
        need: &RangePlanDelta,
    ) -> Selection {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        // The still-needed count drives how much parallelism to fill.
        let want = need.len().max(1);
        let effective = ContentRequest {
            parallelism: req.effective_parallelism().min(want).max(1),
            ..req.clone()
        };
        // Candidate population = every eligible registry peer (the freshly-learned view), so a peer
        // that recovered or a newly-fed candidate can be chosen. `active` peers are de-ranked.
        let pool: Vec<PeerId> = inner
            .registry
            .iter()
            .filter(|e| e.is_eligible())
            .map(|e| e.peer_id)
            .collect();
        self.select_over(&mut inner, &effective, &pool, active, now)
    }

    /// Core selection over an explicit candidate-id `pool`, de-ranking `deranked` peers. Shared by
    /// `select` and `rebalance` so the invariants hold identically for both (SPEC §4.4, §5.5).
    fn select_over(
        &self,
        inner: &mut Inner,
        req: &ContentRequest,
        pool: &[PeerId],
        deranked: &[PeerId],
        now: u64,
    ) -> Selection {
        // Reclaim any dispatch whose outcome never arrived before scoring (#179 finding 1): a peer
        // dispatched to and then gone silent must not keep counting as busy / unevictable forever.
        inner.registry.reclaim_stale_in_flight(now);
        if pool.is_empty() {
            return Selection::empty();
        }

        // Score every eligible pooled peer ONCE (#179 LOW finding: a separate `proven_score_bounds`
        // pre-pass used to re-score every non-cold peer before this loop scored everyone again,
        // doubling score_peer calls on the hot decision path). Score with bonus=0 first — a cold
        // peer's `effective_score` under `score_peer` is exactly the bonus and nothing else depends on
        // it (headroom/exploratory/tie_break are bonus-independent, SPEC §4.4-E), so the proven-score
        // bounds can be derived from this single pass and the bonus applied to cold entries afterward.
        let mut scored: Vec<(PeerId, ScoredPeer)> = Vec::with_capacity(pool.len());
        for id in pool {
            let Some(entry) = inner.registry.get(id) else {
                continue;
            };
            if !entry.is_eligible() {
                continue;
            }
            scored.push((*id, score_peer(entry, &inner.saturation, &inner.relay, 0.0)));
        }
        if scored.is_empty() {
            return Selection::empty();
        }

        // Exploration bonus: a cold peer scores just ABOVE the worst proven peer (so it gets tried)
        // but strictly BELOW the best proven peer (so it never displaces a proven fast peer for the
        // bulk of a transfer — SPEC §4.4-E). We place it a small fraction of the proven-score gap
        // above the worst; when there are no proven peers (all-cold pool) the bonus is 0 and cold
        // peers simply order among themselves. Derived from the single scored pass above (skipping
        // cold/bad-source entries, both identifiable from the already-computed `ScoredPeer`s).
        let (worst_proven, best_proven) = proven_score_bounds(&scored);
        let exploration_bonus = if best_proven > worst_proven {
            // A quarter of the way up from worst to best: above the worst proven peer, below the best.
            worst_proven + 0.25 * (best_proven - worst_proven)
        } else if best_proven > 0.0 {
            // A single proven peer (worst == best): explore just below it so it stays rank 0.
            best_proven * 0.5
        } else {
            0.0
        };

        // Apply the now-known bonus to every cold (exploratory) entry — this is the only field a
        // cold peer's score depends on (SPEC §4.4-E) — then the SPEC §5.5 de-rank pass for `rebalance`.
        for (id, s) in &mut scored {
            if s.exploratory {
                s.effective_score = exploration_bonus;
            }
            // De-rank an already-active peer: shrink its headroom to reflect that it is busy, and
            // discount its score so a replacement is preferred (SPEC §5.5).
            if deranked.contains(id) {
                s.effective_score *= DERANK_FACTOR;
                s.headroom = s.headroom.saturating_sub(1);
            }
        }

        // Advance the epoch (this select/rebalance) for anti-starvation exploration coverage.
        inner.epoch = inner.epoch.wrapping_add(1);
        let epoch = inner.epoch;

        // Cap how many COLD exploratory peers may appear so unmeasured peers don't crowd out proven
        // ones for the bulk of a transfer (SPEC §4.4-E). At least one exploratory slot so an all-cold
        // network still makes progress; otherwise a small fraction of the requested parallelism.
        let want = req.effective_parallelism();
        let explore_cap = explore_slots(want);

        // Rank: highest effective_score first; deterministic tie-break (SPEC §4.4-F). Among equal COLD
        // exploratory peers, order by least-recently-selected (coverage), then seeded jitter (fair yet
        // reproducible); everything else tie-breaks by stable salt. Proven peers have strictly higher
        // effective scores than cold peers (§4.4-A/E), so they always sort ahead.
        let last_sel: Vec<u64> = scored
            .iter()
            .map(|(id, _)| inner.last_selected.get(id).copied().unwrap_or(0))
            .collect();
        let jitter: Vec<u64> = scored.iter().map(|_| inner.rng.gen::<u64>()).collect();
        let mut order: Vec<usize> = (0..scored.len()).collect();
        order.sort_by(|&a, &b| {
            let (_, sa) = &scored[a];
            let (_, sb) = &scored[b];
            sb.effective_score
                .partial_cmp(&sa.effective_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    if sa.exploratory && sb.exploratory {
                        last_sel[a]
                            .cmp(&last_sel[b])
                            .then_with(|| jitter[a].cmp(&jitter[b]))
                    } else {
                        sa.tie_break.cmp(&sb.tie_break)
                    }
                })
        });

        // ANTI-STARVATION re-exploration (SPEC §4.4-E "every candidate is tried" + §4.4-D "a degraded
        // peer that recovers must rise again"). At low parallelism a proven peer can monopolize the
        // only slot forever, so a peer never re-probed can never be re-measured — a fresh newcomer, a
        // cold candidate, or a degraded-then-recovered peer would be invisible. We therefore reserve
        // ONE slot for the MOST-STARVED eligible peer: the one not selected for the longest (cold peers
        // have `last_selected == 0` = maximally starved). It is force-included ONLY when its staleness
        // exceeds a round-robin threshold (~ the eligible pool size), so proven peers still serve the
        // bulk of every transfer; it is placed LAST so it never displaces a proven peer from rank 0
        // when `want > 1`. Marked exploratory (it is an uncertainty probe, not a proven pick).
        let eligible = scored.len().max(1);
        let starve_threshold = eligible as u64; // give each peer a turn within ~one pool sweep
                                                // Forcing is only meaningful when there is genuine competition for slots (`want < eligible`).
                                                // When every eligible peer already fits (`want >= eligible`), natural score order stands — a
                                                // proven peer keeps rank 0 and no re-probe reordering is needed (this is what keeps the
                                                // measured-fast peer ahead of a measured-slow one when both are selected).
        let forced: Option<usize> = if want < eligible {
            scored
                .iter()
                .enumerate()
                .filter(|(idx, (_, s))| {
                    // A verification-failing bad source is never force-explored (SPEC §9.4 keeps it down).
                    s.effective_score > -1.0e11 && {
                        let staleness = epoch.saturating_sub(last_sel[*idx]);
                        staleness >= starve_threshold
                    }
                })
                .max_by(|(ia, (_, sa)), (ib, (_, sb))| {
                    let stale_a = epoch.saturating_sub(last_sel[*ia]);
                    let stale_b = epoch.saturating_sub(last_sel[*ib]);
                    stale_a
                        .cmp(&stale_b)
                        .then_with(|| sb.tie_break.cmp(&sa.tie_break)) // deterministic
                })
                .map(|(idx, _)| idx)
        } else {
            None
        };

        // Pass 1: take the top-scored peers up to `want`, honoring the exploration cap; reserve one
        // slot for the forced-coverage peer (cap at `want - 1`) so it always fits. At `want == 1` the
        // forced peer takes the sole slot THIS round (a periodic re-probe); because a selected peer's
        // staleness resets, the best peer reclaims the slot in the intervening rounds — so the stream
        // still exploits the best peer most of the time while guaranteeing the starved peer is
        // periodically re-measured (SPEC §4.4-D/E).
        let cap_pass1 = if forced.is_some() {
            want.saturating_sub(1)
        } else {
            want
        };
        // The forced-coverage pick consumes one exploration slot (it is an exploratory re-probe), so
        // the total number of exploratory peers — pass-1 cold picks PLUS the forced pick — never
        // exceeds `explore_cap` (SPEC §4.4-E: unmeasured/uncertain peers never crowd out proven ones).
        let forced_is_exploratory = forced.map(|i| scored[i].1.exploratory).unwrap_or(false);
        let explore_budget_pass1 = if forced_is_exploratory {
            explore_cap.saturating_sub(1)
        } else {
            explore_cap
        };
        let mut chosen: Vec<usize> = Vec::with_capacity(want);
        let mut explore_used = 0usize;
        for &i in &order {
            if chosen.len() >= cap_pass1 {
                break;
            }
            if Some(i) == forced {
                continue; // reserved for pass 2
            }
            let (_, s) = &scored[i];
            if s.exploratory {
                if explore_used >= explore_budget_pass1 {
                    continue;
                }
                explore_used += 1;
            }
            chosen.push(i);
        }
        // Pass 2: append the forced-coverage peer in its reserved slot (lowest rank), if not already in.
        if let Some(fi) = forced {
            if chosen.len() < want && !chosen.contains(&fi) {
                chosen.push(fi);
            }
        }

        // Materialize the selection, recording each chosen peer's selection epoch (anti-starvation).
        let mut selection = Selection::empty();
        for (rank, &i) in chosen.iter().enumerate() {
            let (peer_id, s) = scored[i];
            inner.last_selected.insert(peer_id, epoch);
            // A forced-coverage pick of an otherwise-proven peer is still flagged exploratory (it is an
            // uncertainty re-probe, not a merit selection) so the host/executor treats it accordingly.
            let exploratory = s.exploratory || Some(i) == forced;
            selection.peers.push(SelectedPeer {
                peer_id,
                rank: rank as u32,
                max_concurrency: s.headroom.max(1),
                exploratory,
            });
        }

        // Account the dispatch: bump in-flight + record the concurrency each peer will run under, so a
        // later outcome attributes the saturation observation correctly (SPEC §4.1, §5.3).
        for sp in &selection.peers {
            let class = inner
                .registry
                .get(&sp.peer_id)
                .map(|e| PeerClass::of(e.connection_class))
                .unwrap_or(PeerClass::Unknown);
            let in_flight_at_dispatch = inner
                .registry
                .get(&sp.peer_id)
                .map(|e| e.quality.in_flight)
                .unwrap_or(0);
            inner
                .registry
                .add_in_flight(&sp.peer_id, sp.max_concurrency, now);
            // Record dispatch context for the range indices this peer will serve. We do not know exact
            // indices here, so key by a rolling per-peer marker; the outcome's own range index keys
            // the lookup and falls back to the peer's recorded context.
            inner.dispatched.insert(
                (sp.peer_id, usize::MAX),
                DispatchRecord {
                    in_flight_at_dispatch,
                    class,
                },
            );
        }

        selection
    }

    /// **`record_outcome`** — fold a measured result back into the models in real time (SPEC §5.2).
    ///
    /// Derives throughput strictly from measured `bytes / duration_ms` (never a self-reported rate,
    /// SPEC §9.3); updates throughput/RTT/reliability (SPEC §3.2, §3.4), the per-class saturation
    /// model (SPEC §4.1), the adaptive relayed penalty (SPEC §4.2), and decrements in-flight (SPEC
    /// §5.3). An outcome for an unknown peer upserts a cold entry first (self-healing, SPEC §5.2).
    pub fn record_outcome(&self, outcome: &TransferOutcome) {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");

        // Self-heal: an outcome for an unknown peer registers it cold first (SPEC §5.2).
        if inner.registry.get(&outcome.peer_id).is_none() {
            let cand = Candidate::new(outcome.peer_id, Vec::new());
            inner.registry.upsert_candidate(&cand, Provenance::Nat, now);
            // The self-heal upsert may have evicted a different over-capacity entry — prune its
            // side-map residue (#179 finding 2).
            inner.prune_evicted_side_maps();
        }

        // Retrieve the dispatch context for saturation attribution (SPEC §4.1) before mutating.
        let range_index = match outcome.kind {
            OutcomeKind::Range { index, .. } => index,
            OutcomeKind::Request { .. } => usize::MAX,
        };
        let dispatch = inner
            .dispatched
            .remove(&(outcome.peer_id, range_index))
            .or_else(|| inner.dispatched.remove(&(outcome.peer_id, usize::MAX)));
        let class = dispatch.map(|d| d.class).unwrap_or_else(|| {
            inner
                .registry
                .get(&outcome.peer_id)
                .map(|e| PeerClass::of(e.connection_class))
                .unwrap_or(PeerClass::Unknown)
        });
        let in_flight_at_dispatch =
            dispatch
                .map(|d| d.in_flight_at_dispatch)
                .unwrap_or_else(|| {
                    inner
                        .registry
                        .get(&outcome.peer_id)
                        .map(|e| e.quality.in_flight)
                        .unwrap_or(1)
                });

        let throughput = outcome.throughput_bps();

        // Fold into the learned aggregate models (saturation + relay) — measured throughput only.
        if let (Some(bps), true) = (throughput, outcome.is_success()) {
            inner.saturation.observe(class, in_flight_at_dispatch, bps);
            inner.relay.observe(class.is_relayed(), bps);
        }

        // Fold into the per-peer quality model.
        if let Some(entry) = inner.registry.get_mut(&outcome.peer_id) {
            apply_outcome_to_quality(&mut entry.quality, outcome, throughput);
            entry.quality.bump_samples();
            entry.last_outcome_at = Some(outcome.at.max(now));
        }
        // Decrement in-flight: one range settled (SPEC §5.3, symmetric with the `select` dispatch bump).
        inner.registry.release_in_flight(&outcome.peer_id, 1);
    }

    /// Consume a `dig-gossip` churn event to keep the registry live (SPEC §5.4, §2.3). Byte-compatible
    /// with `dig_gossip::PoolEvent` (see [`crate::pool_event`]).
    pub fn on_pool_event(&self, event: &PoolEvent) {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        match event {
            PoolEvent::PeerAdded { peer_id, .. } => {
                inner
                    .registry
                    .mark_connected(*peer_id, Provenance::Gossip, now);
                // Insertion may have evicted a different over-capacity entry (#179 finding 2).
                inner.prune_evicted_side_maps();
            }
            PoolEvent::PeerRemoved { peer_id, reason } => {
                let banned = matches!(reason, PoolRemovalReason::Banned);
                inner.registry.mark_disconnected(peer_id, banned);
                // A plain disconnect never deletes the entry (SPEC §2.3), so nothing to prune here.
            }
        }
    }

    /// Attach / update a live peer's connection class from `dig-nat` (SPEC §5.4, §7.3).
    pub fn on_connection_class(&self, peer: &PeerId, class: TraversalKind) {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        inner.registry.set_connection_class(*peer, class, now);
        // Insertion may have evicted a different over-capacity entry (#179 finding 2).
        inner.prune_evicted_side_maps();
    }

    /// Manually upsert a candidate (seed / bootstrap feed, SPEC §5.4). A fresh peer is cold.
    pub fn upsert_candidate(&self, candidate: &Candidate) {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        inner
            .registry
            .upsert_candidate(candidate, Provenance::Manual, now);
        // Insertion may have evicted a different over-capacity entry (#179 finding 2).
        inner.prune_evicted_side_maps();
    }

    /// Explicitly remove a peer (rare; churn usually drives this — SPEC §5.4). A peer with a range in
    /// flight is retained until it settles.
    pub fn remove_peer(&self, peer: &PeerId) {
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        inner.registry.remove(peer);
        // The removal itself must prune the same peer's side-map residue (#179 finding 2).
        inner.prune_evicted_side_maps();
    }

    /// Explicitly note that `count` ranges were dispatched to `peer` (SPEC §5.3). Optional: `select`
    /// already accounts the dispatch it returns; the host uses this only if it dispatches outside a
    /// `select` result.
    pub fn on_dispatch(&self, peer: &PeerId, count: u32) {
        let now = self.now();
        let mut inner = self.inner.lock().expect("selector mutex poisoned");
        inner.registry.add_in_flight(peer, count, now);
    }

    // ---- Read-only observability (SPEC §5.7) ------------------------------------------------

    /// A read-only snapshot of one peer's learned model, or `None` if unknown (SPEC §5.7).
    pub fn peer_snapshot(&self, peer: &PeerId) -> Option<PeerSnapshot> {
        let inner = self.inner.lock().expect("selector mutex poisoned");
        inner.registry.get(peer).map(PeerSnapshot::of)
    }

    /// A read-only snapshot of the selector's learned aggregate state (SPEC §5.7). Includes the
    /// engine's internal side-map sizes (`last_selected_len`, `dispatched_len`) so a host can confirm
    /// they track the live registry population rather than growing unboundedly (#179 finding 2).
    pub fn snapshot(&self) -> SelectorSnapshot {
        let inner = self.inner.lock().expect("selector mutex poisoned");
        SelectorSnapshot::build(
            inner.registry.iter(),
            &inner.saturation,
            &inner.relay,
            inner.last_selected.len(),
            inner.dispatched.len(),
        )
    }

    /// The current registry size (SPEC §5.7).
    pub fn registry_size(&self) -> usize {
        let inner = self.inner.lock().expect("selector mutex poisoned");
        inner.registry.len()
    }
}

/// De-rank multiplier for an already-active peer during `rebalance` (SPEC §5.5): its score is scaled
/// down so a fresh replacement is preferred for the still-needed ranges.
const DERANK_FACTOR: f64 = 0.5;

/// How many COLD exploratory peers may appear in a selection of size `want` (SPEC §4.4-E): at least
/// one (so an all-cold network makes progress), otherwise ~a third of the requested parallelism so
/// unmeasured peers never dominate the bulk of a transfer.
fn explore_slots(want: usize) -> usize {
    want.div_ceil(3).max(1)
}

/// The worst + best *proven* (non-cold, non-bad) effective score among an already-scored pool, so the
/// exploration bonus sits just above the worst proven peer (SPEC §4.4-E). Returns `(0.0, 0.0)` when
/// there are no proven peers (an all-cold pool) — exploration then simply orders cold peers among
/// themselves.
///
/// Takes the pool's `ScoredPeer`s (scored with `exploration_bonus=0.0`) rather than re-scoring from
/// the registry (#179 LOW finding) — a proven (non-cold, non-bad-source) peer's score does not depend
/// on the exploration bonus at all (SPEC §4.4: the bonus only ever appears in the cold branch), so
/// scoring once and filtering is equivalent to the old two-pass approach, at half the `score_peer`
/// calls.
fn proven_score_bounds(scored: &[(PeerId, ScoredPeer)]) -> (f64, f64) {
    let mut worst = f64::INFINITY;
    let mut best = f64::NEG_INFINITY;
    let mut any = false;
    for (_, s) in scored {
        if s.exploratory {
            continue; // cold — not a "proven" bound
        }
        if s.effective_score <= -1.0e11 {
            continue; // a bad source floor — not a "proven good" bound
        }
        any = true;
        worst = worst.min(s.effective_score);
        best = best.max(s.effective_score);
    }
    if any {
        (worst.max(0.0), best.max(0.0))
    } else {
        (0.0, 0.0)
    }
}

/// Fold one measured outcome into a peer's quality model (SPEC §3.2, §3.4). Throughput/RTT move only
/// on a success with a derivable rate; reliability moves on every peer-attributable result.
fn apply_outcome_to_quality(
    quality: &mut PeerQuality,
    outcome: &TransferOutcome,
    throughput: Option<f64>,
) {
    match outcome.result {
        OutcomeResult::Success => {
            if let Some(bps) = throughput {
                quality.observe_throughput(bps);
            }
            if let Some(rtt) = outcome.rtt_ms {
                quality.observe_rtt(rtt as f64);
            }
            quality.observe_result(true, false);
        }
        OutcomeResult::Failure { reason } => {
            if reason.blames_peer() {
                quality.observe_result(false, reason.is_hard());
            }
        }
        OutcomeResult::Interrupted { .. } => {
            // A partial transfer that dropped: a soft reliability failure (it left a range straggling).
            quality.observe_result(false, false);
        }
    }
}

/// The `peer_id`s of a candidate slice (dispatch pool for `select`).
fn candidate_ids(candidates: &[Candidate]) -> Vec<PeerId> {
    candidates.iter().map(|c| c.peer_id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SelectorConfig;
    use crate::scoring::{SCORE_PEER_CALLS, SCORE_PEER_CALLS_LOCK};
    use crate::types::{Candidate, OutcomeKind, OutcomeResult, TransferOutcome};
    use dig_dht::{CandidateAddr, ContentId};
    use std::sync::atomic::Ordering;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }
    fn candidate(b: u8) -> Candidate {
        Candidate::new(pid(b), vec![CandidateAddr::direct("10.0.0.1", 9444)])
    }
    fn content() -> ContentId {
        ContentId::store([0x77; 32])
    }

    /// #179 LOW finding (select/rebalance double-scores the pool): a single `select` call must invoke
    /// `score_peer` AT MOST ONCE per eligible pooled peer. The old `proven_score_bounds` pre-pass
    /// re-scored every non-cold peer before the main scoring loop scored everyone again, doubling the
    /// work for a mixed cold/proven pool on the hot decision path (rebalance can run over up to ~4096
    /// eligible entries on every dropped source mid-transfer).
    #[test]
    fn select_scores_each_pooled_peer_at_most_once() {
        let sel = PeerSelector::new(SelectorConfig::deterministic(1000, 5));
        // Warm several peers to "proven" (non-cold) status so the old pre-pass had work to do.
        for b in 0..5u8 {
            for i in 0..3u64 {
                sel.record_outcome(&TransferOutcome {
                    peer_id: pid(b),
                    content: content(),
                    kind: OutcomeKind::Range {
                        index: i as usize,
                        offset: 0,
                        length: 1000,
                    },
                    result: OutcomeResult::Success,
                    bytes: 100_000,
                    duration_ms: 1000,
                    rtt_ms: Some(10),
                    at: 1000 + i,
                });
            }
        }
        // Mix in a couple of fresh cold candidates too (a realistic mixed pool).
        let candidates: Vec<Candidate> = (0..7u8).map(candidate).collect();

        // SCORE_PEER_CALLS is process-global (shared across cargo test's parallel threads): serialize
        // via the dedicated lock and measure a delta across just the `select` call, so a concurrently
        // running test's own `score_peer` calls cannot pollute this measurement.
        let _guard = SCORE_PEER_CALLS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = SCORE_PEER_CALLS.load(Ordering::SeqCst);
        let _ = sel.select(&ContentRequest::new(content(), 3), &candidates);
        let calls = SCORE_PEER_CALLS.load(Ordering::SeqCst) - before;
        assert!(
            calls <= candidates.len() as u64,
            "score_peer must run at most once per pooled peer ({} peers), got {calls} calls \
             (a separate proven-bounds pre-pass would double-count the non-cold ones)",
            candidates.len()
        );
    }
}
