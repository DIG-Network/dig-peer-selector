//! Read-only observability snapshots (SPEC.md §5.7) — the agent-friendly / machine-consumable
//! surface.
//!
//! These are **observability only**: reading or serializing them MUST NOT change selection behavior,
//! and they are NOT configuration (SPEC §5.7). They let a node/agent introspect what the selector has
//! learned (a peer's quality, the registry size, the learned saturation points + relayed penalty)
//! without scraping logs or influencing decisions.

use dig_nat::{PeerId, TraversalKind};

use crate::registry::PeerEntry;
use crate::scoring::{PeerClass, RelayModel, SaturationModel};
use crate::types::Provenance;

/// A serializable snapshot of one peer's learned model (SPEC §5.7). Fields are the read-only view of a
/// [`PeerEntry`]'s quality — never an input.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerSnapshot {
    /// The peer identity (64-hex).
    pub peer_id: String,
    /// How the peer entered the registry.
    pub provenance: Provenance,
    /// The observed connection class, if connected.
    pub connection_class: Option<String>,
    /// Whether the peer currently has a live pool link.
    pub connected: bool,
    /// Whether the peer is banned (ineligible until re-added).
    pub banned: bool,
    /// Learned throughput estimate (bytes/sec), or `None` if unmeasured.
    pub throughput_bps: Option<f64>,
    /// Learned RTT estimate (ms), or `None` if unmeasured.
    pub rtt_ms: Option<f64>,
    /// Learned reliability in `[0,1]`, or `None` if unmeasured.
    pub reliability: Option<f64>,
    /// The observed relative volatility of throughput (a tail-risk signal).
    pub throughput_volatility: f64,
    /// Count of measured outcomes folded in (confidence).
    pub samples: u64,
    /// Count of hard (verification) failures observed.
    pub hard_failures: u64,
    /// Ranges currently assigned to this peer (live in-flight).
    pub in_flight: u32,
}

impl PeerSnapshot {
    /// Build a read-only snapshot from a registry entry (SPEC §5.7).
    pub fn of(entry: &PeerEntry) -> Self {
        let q = &entry.quality;
        PeerSnapshot {
            peer_id: entry.peer_id.to_hex(),
            provenance: entry.provenance,
            connection_class: entry.connection_class.map(traversal_kind_name),
            connected: entry.connected,
            banned: entry.banned,
            throughput_bps: q.throughput.value(),
            rtt_ms: q.rtt.value(),
            reliability: q.reliability.rate(),
            throughput_volatility: q.throughput.relative_volatility(),
            samples: q.samples,
            hard_failures: q.reliability.hard_failures(),
            in_flight: q.in_flight,
        }
    }
}

/// A serializable snapshot of the selector's learned aggregate state (SPEC §5.7).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelectorSnapshot {
    /// Current registry size.
    pub registry_size: usize,
    /// Number of peers with at least one measured outcome.
    pub measured_peers: usize,
    /// Number of currently-connected peers.
    pub connected_peers: usize,
    /// Learned saturation point for a direct-path peer class.
    pub saturation_direct: u32,
    /// Learned saturation point for a relayed-path peer class.
    pub saturation_relayed: u32,
    /// Learned saturation point for an unknown-class peer.
    pub saturation_unknown: u32,
    /// The current learned relayed-penalty factor in `[floor, 1.0]`.
    pub relayed_penalty: f64,
    /// Size of the engine's internal `last_selected` side map (anti-starvation bookkeeping, SPEC
    /// §5.1). Exposed so a host can confirm it tracks the live registry population rather than
    /// growing unboundedly with every distinct peer ever fed (#179 finding 2) — observability only,
    /// never an input.
    pub last_selected_len: usize,
    /// Size of the engine's internal `dispatched` side map (saturation-attribution bookkeeping, SPEC
    /// §4.1, §5.3). Same purpose as `last_selected_len` (#179 finding 2).
    pub dispatched_len: usize,
}

impl SelectorSnapshot {
    /// Build the aggregate snapshot from the registry + learned models (SPEC §5.7).
    pub(crate) fn build<'a>(
        entries: impl Iterator<Item = &'a PeerEntry>,
        saturation: &SaturationModel,
        relay: &RelayModel,
        last_selected_len: usize,
        dispatched_len: usize,
    ) -> Self {
        let mut registry_size = 0;
        let mut measured_peers = 0;
        let mut connected_peers = 0;
        for e in entries {
            registry_size += 1;
            if !e.quality.is_cold() {
                measured_peers += 1;
            }
            if e.connected {
                connected_peers += 1;
            }
        }
        SelectorSnapshot {
            registry_size,
            measured_peers,
            connected_peers,
            saturation_direct: saturation.saturation_point(PeerClass::DirectPath),
            saturation_relayed: saturation.saturation_point(PeerClass::RelayedPath),
            saturation_unknown: saturation.saturation_point(PeerClass::Unknown),
            relayed_penalty: relay.penalty(),
            last_selected_len,
            dispatched_len,
        }
    }
}

/// The stable text name of a `dig-nat` connection class (for observability surfaces).
fn traversal_kind_name(k: TraversalKind) -> String {
    match k {
        TraversalKind::Direct => "direct",
        TraversalKind::Upnp => "upnp",
        TraversalKind::NatPmp => "natpmp",
        TraversalKind::Pcp => "pcp",
        TraversalKind::HolePunch => "holepunch",
        TraversalKind::Relayed => "relayed",
    }
    .to_string()
}

/// Helper for callers that hold a raw `PeerId` and want its canonical text form on an observability
/// surface (SPEC §1.3: 64 lower-case hex).
pub fn peer_id_hex(peer: &PeerId) -> String {
    peer.to_hex()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use crate::types::{Candidate, Provenance};
    use dig_dht::CandidateAddr;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }

    #[test]
    fn peer_snapshot_reflects_learned_state() {
        let mut e = PeerEntry::cold(pid(1), Provenance::Dht, 0);
        e.connection_class = Some(TraversalKind::Relayed);
        e.quality.observe_throughput(500.0);
        e.quality.observe_result(true, false);
        e.quality.bump_samples();
        let snap = PeerSnapshot::of(&e);
        assert_eq!(snap.peer_id, pid(1).to_hex());
        assert_eq!(snap.connection_class.as_deref(), Some("relayed"));
        assert_eq!(snap.throughput_bps, Some(500.0));
        assert_eq!(snap.samples, 1);
        // Serializes for the machine-consumable surface.
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"throughput_bps\":500"));
    }

    #[test]
    fn selector_snapshot_counts_and_learned_values() {
        let mut r = Registry::new(100);
        r.mark_connected(pid(1), Provenance::Gossip, 0);
        r.upsert_candidate(
            &Candidate::new(pid(2), vec![CandidateAddr::direct("h", 1)]),
            Provenance::Dht,
            0,
        );
        r.get_mut(&pid(1))
            .unwrap()
            .quality
            .observe_throughput(100.0);
        r.get_mut(&pid(1)).unwrap().quality.bump_samples();
        let sat = SaturationModel::default();
        let relay = RelayModel::default();
        let snap = SelectorSnapshot::build(r.iter(), &sat, &relay, 0, 0);
        assert_eq!(snap.registry_size, 2);
        assert_eq!(snap.measured_peers, 1);
        assert_eq!(snap.connected_peers, 1);
        assert!(snap.saturation_direct >= 1);
        assert!(snap.relayed_penalty > 0.0 && snap.relayed_penalty <= 1.0);
    }

    #[test]
    fn peer_id_hex_helper() {
        assert_eq!(peer_id_hex(&pid(0xAB)), pid(0xAB).to_hex());
    }
}
