//! # dig-peer-selector — the self-optimizing peer-selection middleware of the DIG Node
//!
//! The selector is a pure **decision + learning** layer. It sits between [`dig-download`] (the
//! executor that fetches bytes over [`dig-nat`] mTLS) and the peer-discovery layers ([`dig-dht`],
//! [`dig-gossip`]/`dig-pex`, [`dig-nat`]), and answers one question — *"of these candidate peers,
//! which subset should serve this content, and in what order?"* — learning the answer from the
//! **real, measured outcome** of every transfer it influenced. It has **no user-facing
//! configuration**: every tradeoff (saturation point, relayed penalty, decay) is self-tuned from
//! observed data.
//!
//! This crate is the authoritative implementation of `SPEC.md` (version `1`). The SPEC is the
//! contract; this documentation summarizes it — read `SPEC.md` for the normative statements.
//!
//! ## The closed loop
//!
//! 1. The node calls [`dig_dht::DhtService::find_providers`] and maps the [`ProviderRecord`]s into
//!    [`Candidate`]s, then asks the selector to [`select`](PeerSelector::select) the best subset for a
//!    [`ContentRequest`].
//! 2. `dig-download` executes the multi-source byte-range transfer over `dig-nat` mTLS mux streams.
//! 3. Every per-range / per-request [`TransferOutcome`] streams back via
//!    [`record_outcome`](PeerSelector::record_outcome), updating the models **in real time** so the
//!    next `select` — and a mid-transfer [`rebalance`](PeerSelector::rebalance) — is smarter.
//!
//! ## What is learned (measured-only, non-gameable)
//!
//! A peer's quality is refined EXCLUSIVELY from measured outcomes (SPEC §3, §9.2): there is no input
//! path by which a peer raises its own score, and **observed capacity always overrides advertised**
//! (SPEC §9.3). Throughput/RTT are recency-weighted estimators whose decay is derived from each
//! peer's observed volatility — no baked constant (SPEC §3.2, §4.3). The scorer learns a per-class
//! **saturation point** (anti-thundering-herd, SPEC §4.1) and an adaptive **relayed penalty**
//! (SPEC §4.2), and orients toward **minimizing P99 request latency** (SPEC §4.4).
//!
//! ## Boundaries (what the selector is NOT)
//!
//! It never queries the DHT, runs the gossip pool, opens a socket/TLS session/mux stream, or
//! fetches/verifies/persists bytes — those belong to `dig-dht`, `dig-gossip`, `dig-nat`, and
//! `dig-download` respectively (SPEC §1.2). The selector only *reads their outputs* or *drives their
//! choices*. It re-uses the transport-verified [`PeerId`] (`= SHA-256(TLS SPKI DER)`) and the
//! `dig-dht` content/candidate types verbatim — it defines no parallel identity (SPEC §5, §11).
//!
//! ## Implementers' note — how `dig-node` embeds the selector (P3 integration, digstore)
//!
//! The selector is the **source-selection seam** between `dig-dht` and `dig-download`. `dig-node`
//! wires it as follows (the wiring lives in the node, NOT this crate — SPEC §6.1, §7.4):
//!
//! 1. **Construct** one [`PeerSelector`] per node: `PeerSelector::new(SelectorConfig::default())`.
//! 2. **Feed the registry** continuously:
//!    - subscribe to `dig_gossip::GossipHandle::subscribe_pool_events()` and forward each event —
//!      convert `dig_gossip::PoolEvent` → [`PoolEvent`] with a trivial 1:1 field map (identical
//!      shapes; see [`pool_event`]) — into [`on_pool_event`](PeerSelector::on_pool_event);
//!    - on each established `dig-nat` connection, call
//!      [`on_connection_class`](PeerSelector::on_connection_class) with its
//!      [`dig_nat::TraversalKind`];
//!    - optionally seed from a `connected_pool_peers()` snapshot at startup via
//!      [`upsert_candidate`](PeerSelector::upsert_candidate).
//! 3. **Per content want**, call `find_providers(&content)`, map each [`ProviderRecord`] into a
//!    [`Candidate`] (via [`Candidate::from_provider_record`]), and call
//!    [`select`](PeerSelector::select). Use each [`SelectedPeer`]'s `max_concurrency` as the per-peer
//!    concurrent-range cap in `dig-download` (replacing its built-in `pick_source` heuristic).
//! 4. **Translate the `dig-download` `DownloadEvent` stream into outcomes as it flows** (SPEC §6.2):
//!    map `RangeCompleted` → a `Range` [`TransferOutcome`] with `result: Success`; `RangeFailed` →
//!    `Failure { reason }` (an integrity/verify failure → [`FailureReason::VerificationFailed`]);
//!    optionally `Completed` → a `Request` outcome for whole-request P99 learning. Call
//!    [`record_outcome`](PeerSelector::record_outcome) for each. A `Paused` is NOT a failure — do not
//!    record one (SPEC §6.4).
//! 5. **On a dropped source / relocate**, call [`rebalance`](PeerSelector::rebalance) with the still-
//!    active peers and the still-needed ranges to get a replacement subset (SPEC §5.5). On resume,
//!    `select`/`rebalance` only the ranges NOT in `DownloadState::done_ranges` (SPEC §6.4).
//!
//! Because `TransferOutcome`/`Selection` are defined here structurally, this crate does NOT depend on
//! `dig-download` — avoiding a dependency cycle; the event→outcome mapping lives in the node adapter
//! (SPEC §11).
//!
//! [`dig-download`]: https://github.com/DIG-Network/dig-download
//! [`dig-dht`]: https://github.com/DIG-Network/dig-dht
//! [`dig-nat`]: https://github.com/DIG-Network/dig-nat
//! [`dig-gossip`]: https://github.com/DIG-Network/dig-gossip
//! [`ProviderRecord`]: dig_dht::ProviderRecord

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod engine;
pub mod observe;
pub mod pool_event;
pub mod quality;
pub mod registry;
pub mod scoring;
pub mod types;

// ---- The frozen public surface (SPEC §11) --------------------------------------------------------

pub use config::{ClockSource, SelectorConfig, DEFAULT_REGISTRY_CAPACITY};
pub use engine::PeerSelector;
pub use observe::{peer_id_hex, PeerSnapshot, SelectorSnapshot};
pub use pool_event::{PoolEvent, PoolRemovalReason};
pub use quality::{Estimate, PeerQuality, Reliability};
pub use registry::{FeedResult, PeerEntry};
pub use scoring::{PeerClass, RelayModel, SaturationModel};
pub use types::{
    Candidate, ContentRequest, FailureReason, OutcomeKind, OutcomeResult, Provenance,
    RangePlanDelta, SelectedPeer, Selection, TransferOutcome,
};

// ---- Re-used from the sibling crates (NOT redefined — SPEC §5, §11) ------------------------------

/// The candidate/content types re-used from `dig-dht` (SPEC §7.1): what is fetched + how a provider
/// is addressed.
pub use dig_dht::{AddressKind, CandidateAddr, ContentId, ProviderRecord};
/// The transport-verified peer identity (`peer_id = SHA-256(TLS SPKI DER)`), re-used from `dig-nat`.
pub use dig_nat::PeerId;
/// The `dig-nat` connection-class ladder the selector reads observationally (SPEC §7.3).
pub use dig_nat::TraversalKind;
