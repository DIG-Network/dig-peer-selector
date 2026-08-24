//! Dial hand-off (SPEC §5.8, §11): turning a *ranked identity* into something a caller can actually
//! connect to.
//!
//! The selector still opens no socket. What it removes is the last piece of hand-assembly a consumer
//! had to do between `select` and `dig_peer::DigPeer::connect`: mapping a chosen `peer_id` back to
//! its dial addresses and building a [`PeerTarget`]. Every consumer doing that itself is a second
//! implementation of one shared behavior, which is exactly how the addressing of two crates drifts
//! apart (#1283).
//!
//! For the same reason this module **inherits** the candidate ordering rather than expressing one:
//! [`dig_dht::dial_candidates`] is the ONE place the DHT states it, and it carries three properties
//! that are easy to omit when re-derived — the dialable-kind filter, dedup by `host:port`, and the
//! reserved fallback slot that stops a cap-`MAX_DIAL_CANDIDATES` truncation from excluding every
//! non-IPv6 candidate (the #836 read-leg failure: a v6 attempt must never mask a working v4 one).
//!
//! The [`PeerTarget`] carries the `peer_id`, and `DigPeer::connect` PINS the mTLS handshake to it —
//! so a caller that means to reach peer X cannot be answered by a different CA-valid peer. That
//! pinning is the reason the hand-off is a target and not a bare address list (NC-12: a dialed peer
//! is untrusted, and the addresses it advertised are a hint, never evidence about who it is).

use dig_dht::CandidateAddr;
use dig_peer::PeerTarget;
use std::net::{IpAddr, SocketAddr};

use crate::PeerId;

/// Build the dial target for `peer_id` from its learned candidate addresses.
///
/// Candidates whose host is not an IP literal are dropped FIRST, then the survivors go through
/// [`dig_dht::dial_candidates`] — that order matters: `dial_candidates` bounds the list at
/// [`MAX_DIAL_CANDIDATES`](dig_dht::MAX_DIAL_CANDIDATES), so filtering afterwards would let unusable
/// hostnames occupy cap slots and push a working IP literal out of the result entirely.
///
/// Dropping hostnames at all is this layer's one addition, and it is forced by the output type: a
/// [`PeerTarget`] carries resolved [`SocketAddr`]s, and this crate resolves no DNS on the dial path.
/// DHT candidates are *observed* socket addresses, so a hostname denotes a malformed record.
///
/// Address FAMILY order is applied by `dial_candidates` (IPv6-first, IPv4-fallback) and again by
/// `dig-ip` at dial time against the local host's own families; this layer adds no ordering of its
/// own. When nothing dialable survives, the result is a relay-only target: the peer stays reachable
/// by identity alone rather than becoming unconnectable.
pub fn peer_target(peer_id: PeerId, addresses: &[CandidateAddr], network_id: &str) -> PeerTarget {
    let literals: Vec<CandidateAddr> = addresses
        .iter()
        .filter(|a| socket_of(a).is_some())
        .cloned()
        .collect();

    let sockets: Vec<SocketAddr> = dig_dht::dial_candidates(&literals)
        .into_iter()
        .filter_map(socket_of)
        .collect();

    if sockets.is_empty() {
        PeerTarget::relay_only(peer_id, network_id)
    } else {
        PeerTarget::with_addrs(peer_id, sockets, network_id)
    }
}

/// Resolve one candidate to a dialable socket, or `None` when its host is not an IP literal.
///
/// Parsing the host into an [`IpAddr`] before attaching the port is what makes this correct for IPv6
/// and v4-mapped hosts alike — formatting `host:port` as text would produce `::1:9000`, which is a
/// different (and unparseable) address.
fn socket_of(addr: &CandidateAddr) -> Option<SocketAddr> {
    let ip: IpAddr = addr.host.parse().ok()?;
    Some(SocketAddr::new(ip, addr.port))
}
