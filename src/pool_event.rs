//! [`PoolEvent`] / [`PoolRemovalReason`] — the topology/churn feed, byte-compatible with
//! `dig_gossip::PoolEvent` (SPEC.md §5.4, §7.2).
//!
//! # Why this shape is mirrored, not imported
//!
//! SPEC §5.4/§11 originally required `on_pool_event` to consume `dig_gossip::PoolEvent` **verbatim**.
//! In practice `dig-gossip` pulls the entire chia-protocol / consensus / TLS stack into what is a
//! pure decision layer, and its published git tip does not currently compile as a dependency (it
//! lags the upstream `chia-*` crate versions it references). Taking that dependency would both bloat
//! and *break* this crate's build — contradicting the SPEC's own dependency-minimalism principle
//! (§1, §11) and the `dig-dht` / `dig-pex` precedent, which deliberately avoid `dig-gossip` for
//! exactly this reason.
//!
//! This crate therefore mirrors the churn-event shape locally — **byte-identical** field names and
//! variants, over the SAME re-used [`dig_nat::PeerId`] — exactly as `dig-pex` mirrors the L7 address
//! shape "rather than pulling those crates in." The host adapter (`dig-node`) converts a
//! `dig_gossip::PoolEvent` into this type with a trivial 1:1 field map. Because the shapes are
//! identical, the contract is preserved; the SPEC records this deviation (§5.4, §7.2, §11, SEL-01).
//!
//! When `dig-gossip` is published to crates.io with a compiling tip, this module MAY be replaced by a
//! direct re-export without changing any field name or variant — the shapes are the same.

use std::net::SocketAddr;

use dig_nat::PeerId;

/// A churn event as the connected pool gains or loses a peer — byte-compatible with
/// `dig_gossip::PoolEvent`.
///
/// The host subscribes to `dig-gossip`'s pool events and forwards each one to the selector via
/// [`crate::PeerSelector::on_pool_event`], which keeps the registry live (SPEC §2.3):
/// - `PeerAdded` **upserts** a registry entry (provenance [`crate::Provenance::Gossip`]), preserving
///   any existing learned quality (a reconnecting peer keeps its history — SPEC §2.3);
/// - `PeerRemoved` marks the peer **disconnected** but **retains** its entry + learned quality so a
///   later reconnect resumes from history (subject to eviction — SPEC §2.5); a `Banned` reason makes
///   the peer ineligible for selection until re-added (SPEC §9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolEvent {
    /// A peer was added to the connected pool (dialed successfully, or accepted inbound and adopted).
    PeerAdded {
        /// The verified peer identity now in the pool.
        peer_id: PeerId,
        /// The remote endpoint the connection runs over (peer, or relay for a relayed link).
        addr: SocketAddr,
    },
    /// A peer left the connected pool (disconnected, evicted dead/stale, or banned).
    PeerRemoved {
        /// The peer identity that is no longer connected.
        peer_id: PeerId,
        /// Why it left.
        reason: PoolRemovalReason,
    },
}

/// Why a peer was removed from the pool — byte-compatible with `dig_gossip::PoolRemovalReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRemovalReason {
    /// A normal disconnect (peer closed, or we called `disconnect`).
    Disconnected,
    /// Evicted because keepalive found it dead / unresponsive.
    Dead,
    /// Removed because the peer was banned for misbehaviour — ineligible until re-added (SPEC §9.4).
    Banned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }

    #[test]
    fn pool_event_variants_construct_and_compare() {
        let addr: SocketAddr = "203.0.113.7:9444".parse().unwrap();
        let a = PoolEvent::PeerAdded {
            peer_id: pid(1),
            addr,
        };
        let b = PoolEvent::PeerRemoved {
            peer_id: pid(1),
            reason: PoolRemovalReason::Banned,
        };
        assert_ne!(a, b);
        assert_eq!(
            a.clone(),
            PoolEvent::PeerAdded {
                peer_id: pid(1),
                addr
            }
        );
    }

    #[test]
    fn removal_reasons_are_distinct() {
        assert_ne!(PoolRemovalReason::Disconnected, PoolRemovalReason::Banned);
        assert_ne!(PoolRemovalReason::Dead, PoolRemovalReason::Banned);
    }
}
