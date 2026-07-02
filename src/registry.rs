//! The dynamic peer registry: `peer_id -> PeerEntry`, fed by churn + DHT candidates, bounded with
//! lowest-value eviction (SPEC.md §2).
//!
//! The registry is **fed, not self-discovered** (SPEC §2.3): gossip pool churn upserts/marks entries,
//! and DHT candidates passed to `select` upsert cold entries. A reconnecting peer keeps its learned
//! history (its quality is retained across a disconnect — SPEC §2.3). The registry is bounded (a
//! resource limit, not a behavior knob) and evicts the lowest-value entries first, never a connected
//! peer or one with a range in flight (SPEC §2.5).

use std::collections::HashMap;

use dig_dht::CandidateAddr;
use dig_nat::{PeerId, TraversalKind};

use crate::quality::PeerQuality;
use crate::types::{Candidate, Provenance};

/// One registry entry: identity, reachability, live-link class, provenance, and the learned quality
/// model (SPEC §2.1). Field names are the API contract; private bookkeeping fields are added below.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// The registry key: `peer_id = SHA-256(TLS SPKI DER)` (SPEC §1.3, re-used from `dig-nat`).
    pub peer_id: PeerId,
    /// Dial candidates, byte-compatible with `dig-dht` provider records / the L7 `dig.getPeers` shape.
    pub addresses: Vec<CandidateAddr>,
    /// The `dig-nat` tier of the live link, if connected — observational only (SPEC §2.1, §7.3).
    pub connection_class: Option<TraversalKind>,
    /// How this peer entered the registry (strongest-evidence provenance kept — SPEC §2.2).
    pub provenance: Provenance,
    /// The learned quality model (SPEC §3) — MEASURED-only.
    pub quality: PeerQuality,
    /// Unix seconds when first registered.
    pub first_seen: u64,
    /// Unix seconds of the most recent measured outcome, if any.
    pub last_outcome_at: Option<u64>,
    /// Whether the peer currently has a live pool link (SPEC §2.3). A disconnected peer is retained
    /// (with its quality) but is a weaker eviction-protection candidate.
    pub connected: bool,
    /// Whether the peer is banned — ineligible for selection until re-added (SPEC §9.4).
    pub banned: bool,
}

impl PeerEntry {
    /// A fresh, cold entry for `peer_id` first seen at `now` with the given provenance (SPEC §2.3,
    /// §3.5). Its quality is cold, so its first selection is exploratory (SPEC §4.4-E).
    pub fn cold(peer_id: PeerId, provenance: Provenance, now: u64) -> Self {
        PeerEntry {
            peer_id,
            addresses: Vec::new(),
            connection_class: None,
            provenance,
            quality: PeerQuality::cold(),
            first_seen: now,
            last_outcome_at: None,
            connected: false,
            banned: false,
        }
    }

    /// Whether this peer is eligible for selection: not banned (SPEC §9.4). (Disconnected peers stay
    /// eligible — they may be reachable via a fresh dial; only a ban excludes.)
    pub fn is_eligible(&self) -> bool {
        !self.banned
    }

    /// Whether this entry may be evicted: never a connected peer or one with a range in flight
    /// (SPEC §2.5).
    pub fn is_evictable(&self) -> bool {
        !self.connected && self.quality.in_flight == 0
    }

    /// The most-direct dial address (lowest [`dig_dht::AddressKind::rank`]), if any (SPEC §2.1). The
    /// registry sorts most-direct-first on demand and never assumes wire order.
    pub fn preferred_address(&self) -> Option<&CandidateAddr> {
        self.addresses
            .iter()
            .filter(|a| a.kind.is_dialable())
            .min_by_key(|a| a.kind.rank())
    }

    /// An eviction *value* score (higher = more valuable = evict later). Combines staleness (age of
    /// the last measured outcome) with learned quality + confidence, per SPEC §2.5. A never-measured,
    /// long-idle peer scores lowest and is shed first.
    pub(crate) fn eviction_value(&self, now: u64) -> f64 {
        // Quality contribution: measured throughput weighted by confidence + reliability.
        let tput = self.quality.throughput.value().unwrap_or(0.0);
        let conf = self.quality.confidence();
        let rel = self.quality.reliability.rate().unwrap_or(0.0);
        let quality_value = tput * conf * (0.5 + 0.5 * rel);
        // Staleness penalty: older last-outcome => lower value. A peer never measured is maximally
        // stale (uses first_seen as the reference so a fresh cold peer isn't instantly evicted).
        let reference = self.last_outcome_at.unwrap_or(self.first_seen);
        let age = now.saturating_sub(reference) as f64;
        // Decay value by age (a soft, monotone penalty; a day-old idle peer is heavily discounted).
        let recency = 1.0 / (1.0 + age / 3600.0);
        quality_value * recency + recency // + recency so ties break toward the fresher peer
    }
}

/// Outcome of feeding a churn/candidate event into the registry (for the engine + tests to assert on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedResult {
    /// A brand-new (cold) entry was created.
    Inserted,
    /// An existing entry was updated (quality preserved).
    Updated,
    /// An existing entry was marked disconnected (its quality retained).
    MarkedDisconnected,
    /// The event referred to a peer that was not present (a no-op removal).
    Absent,
}

/// The peer registry (SPEC §2). Owns the `peer_id -> PeerEntry` map and enforces the capacity bound.
#[derive(Debug, Default)]
pub struct Registry {
    entries: HashMap<PeerId, PeerEntry>,
    capacity: usize,
}

impl Registry {
    /// A registry bounded at `capacity` entries (a resource limit, SPEC §2.5).
    pub fn new(capacity: usize) -> Self {
        Registry {
            entries: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// The number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A read-only view of an entry.
    pub fn get(&self, peer: &PeerId) -> Option<&PeerEntry> {
        self.entries.get(peer)
    }

    /// A mutable view of an entry (engine-internal).
    pub(crate) fn get_mut(&mut self, peer: &PeerId) -> Option<&mut PeerEntry> {
        self.entries.get_mut(peer)
    }

    /// Iterate all entries (read-only).
    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.entries.values()
    }

    /// Upsert a peer from a **candidate** (DHT/manual feed, SPEC §2.3). A new peer is created cold
    /// (its first selection is exploratory); an existing peer keeps its learned quality but refreshes
    /// its addresses/class and, if the new provenance is stronger evidence, its provenance. Returns
    /// whether an entry was created or updated. Enforces the capacity bound after an insert.
    pub fn upsert_candidate(
        &mut self,
        candidate: &Candidate,
        provenance: Provenance,
        now: u64,
    ) -> FeedResult {
        let result = match self.entries.get_mut(&candidate.peer_id) {
            Some(existing) => {
                if !candidate.addresses.is_empty() {
                    existing.addresses = candidate.addresses.clone();
                }
                if candidate.class.is_some() {
                    existing.connection_class = candidate.class;
                }
                if provenance.evidence() > existing.provenance.evidence() {
                    existing.provenance = provenance;
                }
                FeedResult::Updated
            }
            None => {
                let mut entry = PeerEntry::cold(candidate.peer_id, provenance, now);
                entry.addresses = candidate.addresses.clone();
                entry.connection_class = candidate.class;
                self.seed_class_prior(&mut entry);
                self.entries.insert(candidate.peer_id, entry);
                FeedResult::Inserted
            }
        };
        if matches!(result, FeedResult::Inserted) {
            self.enforce_capacity(now);
        }
        result
    }

    /// Mark a peer **connected** (a live pool link from `PeerAdded`), upserting a cold entry if new
    /// and preserving any existing learned quality (SPEC §2.3). Provenance `Gossip`.
    pub fn mark_connected(&mut self, peer: PeerId, provenance: Provenance, now: u64) -> FeedResult {
        match self.entries.get_mut(&peer) {
            Some(existing) => {
                existing.connected = true;
                existing.banned = false;
                if provenance.evidence() > existing.provenance.evidence() {
                    existing.provenance = provenance;
                }
                FeedResult::Updated
            }
            None => {
                let mut entry = PeerEntry::cold(peer, provenance, now);
                entry.connected = true;
                self.entries.insert(peer, entry);
                self.enforce_capacity(now);
                FeedResult::Inserted
            }
        }
    }

    /// Mark a peer **disconnected** (`PeerRemoved`) — its entry AND learned quality are RETAINED so a
    /// reconnect resumes from history (SPEC §2.3). A `banned` flag makes it ineligible until re-added
    /// (SPEC §9.4). Returns `Absent` if the peer was unknown.
    pub fn mark_disconnected(&mut self, peer: &PeerId, banned: bool) -> FeedResult {
        match self.entries.get_mut(peer) {
            Some(existing) => {
                existing.connected = false;
                if banned {
                    existing.banned = true;
                }
                FeedResult::MarkedDisconnected
            }
            None => FeedResult::Absent,
        }
    }

    /// Attach / update a live peer's connection class from `dig-nat` (SPEC §5.4, §7.3). Upserts a cold
    /// entry (provenance `Nat`) if the peer is not yet known, seeding its class prior.
    pub fn set_connection_class(
        &mut self,
        peer: PeerId,
        class: TraversalKind,
        now: u64,
    ) -> FeedResult {
        match self.entries.get_mut(&peer) {
            Some(existing) => {
                existing.connection_class = Some(class);
                FeedResult::Updated
            }
            None => {
                let mut entry = PeerEntry::cold(peer, Provenance::Nat, now);
                entry.connection_class = Some(class);
                self.seed_class_prior(&mut entry);
                self.entries.insert(peer, entry);
                self.enforce_capacity(now);
                FeedResult::Inserted
            }
        }
    }

    /// Explicitly remove a peer (rare; churn usually drives this — SPEC §5.4). A peer with a range in
    /// flight is NOT removed (removing it would corrupt in-flight accounting).
    pub fn remove(&mut self, peer: &PeerId) -> FeedResult {
        match self.entries.get(peer) {
            Some(e) if e.quality.in_flight > 0 => FeedResult::Updated, // keep — busy
            Some(_) => {
                self.entries.remove(peer);
                FeedResult::MarkedDisconnected
            }
            None => FeedResult::Absent,
        }
    }

    /// Record that `count` ranges were dispatched to `peer` (in-flight bump, SPEC §5.3).
    pub(crate) fn add_in_flight(&mut self, peer: &PeerId, count: u32) {
        if let Some(e) = self.entries.get_mut(peer) {
            e.quality.in_flight = e.quality.in_flight.saturating_add(count);
        }
    }

    /// Record that a range dispatched to `peer` settled (in-flight decrement, SPEC §5.3).
    pub(crate) fn release_in_flight(&mut self, peer: &PeerId, count: u32) {
        if let Some(e) = self.entries.get_mut(peer) {
            e.quality.in_flight = e.quality.in_flight.saturating_sub(count);
        }
    }

    /// Seed the connection-class **prior** on a fresh cold entry (SPEC §3.3). A `Relayed` peer starts
    /// no better than a direct peer (it is not *preferred* before measured); the prior is subordinate
    /// to measured outcomes. We seed only reliability-neutral priors here — the magnitude of any
    /// relayed throughput handicap is learned by the scorer (SPEC §4.2), not baked as a constant.
    fn seed_class_prior(&self, entry: &mut PeerEntry) {
        // Cold peers get a neutral reliability prior so exploration treats them as uncertain, not
        // failed. No throughput prior is seeded (leaving throughput unmeasured => exploratory).
        entry.quality.reliability.seed_prior(0.5);
    }

    /// Enforce the capacity bound: while over capacity, evict the lowest eviction-value evictable
    /// entry (never a connected/in-flight peer — SPEC §2.5). Eviction discards learned quality; a
    /// re-learned peer starts cold again.
    fn enforce_capacity(&mut self, now: u64) {
        while self.entries.len() > self.capacity {
            let victim = self
                .entries
                .values()
                .filter(|e| e.is_evictable())
                .min_by(|a, b| {
                    a.eviction_value(now)
                        .partial_cmp(&b.eviction_value(now))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|e| e.peer_id);
            match victim {
                Some(id) => {
                    self.entries.remove(&id);
                }
                // Everything left is protected (connected / in-flight) — cannot shed further.
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::AddressKind;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }
    fn cand(b: u8) -> Candidate {
        Candidate::new(pid(b), vec![CandidateAddr::direct("10.0.0.1", 9444)])
    }

    #[test]
    fn upsert_candidate_inserts_cold_then_updates_preserving_quality() {
        let mut r = Registry::new(100);
        assert_eq!(
            r.upsert_candidate(&cand(1), Provenance::Dht, 100),
            FeedResult::Inserted
        );
        assert!(r.get(&pid(1)).unwrap().quality.is_cold());
        // Simulate learning.
        r.get_mut(&pid(1))
            .unwrap()
            .quality
            .observe_throughput(500.0);
        r.get_mut(&pid(1)).unwrap().quality.bump_samples();
        // A re-upsert keeps the learned quality.
        assert_eq!(
            r.upsert_candidate(&cand(1), Provenance::Dht, 200),
            FeedResult::Updated
        );
        assert!(!r.get(&pid(1)).unwrap().quality.is_cold());
    }

    #[test]
    fn disconnect_retains_entry_and_quality() {
        let mut r = Registry::new(100);
        r.mark_connected(pid(1), Provenance::Gossip, 100);
        r.get_mut(&pid(1))
            .unwrap()
            .quality
            .observe_throughput(700.0);
        r.get_mut(&pid(1)).unwrap().quality.bump_samples();
        assert_eq!(
            r.mark_disconnected(&pid(1), false),
            FeedResult::MarkedDisconnected
        );
        let e = r.get(&pid(1)).unwrap();
        assert!(!e.connected);
        assert!(!e.quality.is_cold(), "quality retained across disconnect");
        assert!(e.is_eligible(), "a plain disconnect stays eligible");
    }

    #[test]
    fn banned_peer_is_ineligible_until_reconnect() {
        let mut r = Registry::new(100);
        r.mark_connected(pid(1), Provenance::Gossip, 100);
        r.mark_disconnected(&pid(1), true);
        assert!(!r.get(&pid(1)).unwrap().is_eligible());
        // Re-adding (reconnect) clears the ban.
        r.mark_connected(pid(1), Provenance::Gossip, 200);
        assert!(r.get(&pid(1)).unwrap().is_eligible());
    }

    #[test]
    fn stronger_provenance_wins_weaker_ignored() {
        let mut r = Registry::new(100);
        r.upsert_candidate(&cand(1), Provenance::Pex, 100);
        r.upsert_candidate(&cand(1), Provenance::Dht, 100);
        assert_eq!(r.get(&pid(1)).unwrap().provenance, Provenance::Dht);
        // A weaker provenance does not downgrade.
        r.upsert_candidate(&cand(1), Provenance::Pex, 100);
        assert_eq!(r.get(&pid(1)).unwrap().provenance, Provenance::Dht);
    }

    #[test]
    fn eviction_sheds_lowest_value_never_connected_or_in_flight() {
        let mut r = Registry::new(2);
        // Two connected, high-value peers.
        r.mark_connected(pid(1), Provenance::Gossip, 100);
        r.mark_connected(pid(2), Provenance::Gossip, 100);
        // A third cold, disconnected candidate arrives → over capacity → the lowest-value evictable
        // is shed. The two connected peers are protected, so the new cold one is evicted immediately.
        r.upsert_candidate(&cand(3), Provenance::Dht, 100);
        assert!(r.get(&pid(1)).is_some());
        assert!(r.get(&pid(2)).is_some());
        assert!(
            r.get(&pid(3)).is_none(),
            "connected peers protected; cold candidate evicted"
        );
    }

    #[test]
    fn eviction_prefers_shedding_stale_unmeasured_over_fresh_measured() {
        let mut r = Registry::new(1);
        // A measured, recently-active peer.
        r.upsert_candidate(&cand(1), Provenance::Dht, 100);
        let e = r.get_mut(&pid(1)).unwrap();
        e.quality.observe_throughput(900.0);
        e.quality.bump_samples();
        e.last_outcome_at = Some(1000);
        // A stale cold peer arrives much later → over capacity → the stale cold one should go, not the
        // valuable measured one.
        r.upsert_candidate(&cand(2), Provenance::Dht, 5000);
        assert!(
            r.get(&pid(1)).is_some(),
            "the valuable measured peer survives"
        );
        assert!(r.get(&pid(2)).is_none(), "the stale cold peer is evicted");
    }

    #[test]
    fn in_flight_peer_is_not_removed() {
        let mut r = Registry::new(100);
        r.upsert_candidate(&cand(1), Provenance::Dht, 100);
        r.add_in_flight(&pid(1), 2);
        assert_eq!(r.remove(&pid(1)), FeedResult::Updated); // kept — busy
        assert!(r.get(&pid(1)).is_some());
        r.release_in_flight(&pid(1), 2);
        assert_eq!(r.remove(&pid(1)), FeedResult::MarkedDisconnected);
        assert!(r.get(&pid(1)).is_none());
    }

    #[test]
    fn set_connection_class_upserts_and_attaches() {
        let mut r = Registry::new(100);
        assert_eq!(
            r.set_connection_class(pid(1), TraversalKind::Relayed, 100),
            FeedResult::Inserted
        );
        assert_eq!(
            r.get(&pid(1)).unwrap().connection_class,
            Some(TraversalKind::Relayed)
        );
    }

    #[test]
    fn preferred_address_is_most_direct() {
        let mut r = Registry::new(100);
        let c = Candidate::new(
            pid(1),
            vec![
                CandidateAddr {
                    host: "r".into(),
                    port: 1,
                    kind: AddressKind::Reflexive,
                },
                CandidateAddr::direct("d", 2),
            ],
        );
        r.upsert_candidate(&c, Provenance::Dht, 100);
        assert_eq!(
            r.get(&pid(1)).unwrap().preferred_address().unwrap().kind,
            AddressKind::Direct
        );
    }
}
