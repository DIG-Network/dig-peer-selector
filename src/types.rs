//! The frozen public value types of the selector API (SPEC.md §5.1, §5.2, §5.5).
//!
//! These are the shapes `dig-download`/`dig-node` pass in and get back. Identity, content and
//! candidate-address types are **re-used** from the sibling crates ([`dig_nat::PeerId`],
//! [`dig_dht::ContentId`], [`dig_dht::CandidateAddr`]) — never redefined (SPEC §5, §11).

use dig_dht::{CandidateAddr, ContentId, ProviderRecord};
use dig_nat::{PeerId, TraversalKind};

/// How a peer entered the registry — a hint about *trust of the address*, never a substitute for a
/// measured outcome (SPEC §2.2, §9.1). Provenance MUST NOT by itself raise a peer's quality score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Provenance {
    /// Learned as a `dig-dht` provider record for some content (SPEC §7.1).
    Dht,
    /// Present in the `dig-gossip` connected pool — a live mTLS link (SPEC §7.2).
    Gossip,
    /// Learned via peer exchange — a HINT only, quality unknown until measured (SPEC §7.2, §9.1).
    Pex,
    /// A connection whose class `dig-nat` reported directly.
    Nat,
    /// Injected by the host for testing / bootstrap.
    Manual,
}

impl Provenance {
    /// Evidence strength (higher = stronger). A live pool/nat link outranks a mere DHT/PEX address
    /// hint; the registry keeps the strongest-evidence provenance when a peer is known several ways
    /// (SPEC §2.2). This orders *address trust* only — it never affects the quality score.
    pub(crate) fn evidence(self) -> u8 {
        match self {
            Provenance::Manual => 0,
            Provenance::Pex => 1,
            Provenance::Dht => 2,
            Provenance::Gossip => 3,
            Provenance::Nat => 4,
        }
    }
}

/// What is being fetched and how — the request the selector ranks a candidate set for (SPEC §5.1).
#[derive(Debug, Clone)]
pub struct ContentRequest {
    /// The content id: `Store | Root(capsule) | Resource` (re-used from `dig-dht`).
    pub content: ContentId,
    /// The resource ciphertext length if known (from availability), else `None`.
    pub total_length: Option<u64>,
    /// The planned number of ranges, if known.
    pub range_count: Option<usize>,
    /// How many parallel sources the caller wants (`>= 1`). Bounds the returned subset size.
    pub parallelism: usize,
}

impl ContentRequest {
    /// A request for `content` wanting `parallelism` parallel sources (`>= 1`), lengths unknown.
    pub fn new(content: ContentId, parallelism: usize) -> Self {
        ContentRequest {
            content,
            total_length: None,
            range_count: None,
            parallelism: parallelism.max(1),
        }
    }

    /// The effective parallelism (always `>= 1`).
    pub fn effective_parallelism(&self) -> usize {
        self.parallelism.max(1)
    }
}

/// A peer offered as a possible source for a specific content request (SPEC §5.1).
///
/// Carries at least the `peer_id` and dial `addresses` (typically mapped from a
/// [`dig_dht::ProviderRecord`]), and MAY carry a known connection `class`. Selecting a fresh
/// candidate registers it (cold) as a side effect (SPEC §2.3).
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The transport-verified peer identity (re-used from `dig-nat`).
    pub peer_id: PeerId,
    /// Dial candidate addresses (byte-compatible with `dig-dht` provider records / L7 `dig.getPeers`).
    pub addresses: Vec<CandidateAddr>,
    /// The `dig-nat` connection class of a live link, if known — an observational prior only.
    pub class: Option<TraversalKind>,
}

impl Candidate {
    /// A candidate from a `peer_id` + addresses, no known connection class.
    pub fn new(peer_id: PeerId, addresses: Vec<CandidateAddr>) -> Self {
        Candidate {
            peer_id,
            addresses,
            class: None,
        }
    }

    /// Map a `dig-dht` [`ProviderRecord`] into a candidate. Returns `None` if the record's
    /// `provider_peer_id` is malformed hex (a provider we cannot address is not a candidate).
    ///
    /// A provider record is an **address hint** (SPEC §9.1): the peer is proven to hold the content
    /// only when a transfer from it yields a `Success` outcome.
    ///
    /// Decodes the record's raw `provider_peer_id` hex field directly via **this crate's own**
    /// `dig_nat::PeerId::from_hex`, rather than calling `ProviderRecord::provider_peer_id()` — that
    /// convenience method returns `dig-dht`'s own (transitively older) `dig-nat` version's `PeerId`,
    /// a distinct Rust type from ours once `dig-dht` and `dig-peer-selector` resolve different
    /// `dig-nat` majors. `PeerId` is a pure 32-byte-hex value type, so decoding the wire string
    /// ourselves is exact and version-independent.
    pub fn from_provider_record(rec: &ProviderRecord) -> Option<Self> {
        PeerId::from_hex(&rec.provider_peer_id)
            .map(|peer_id| Candidate::new(peer_id, rec.addresses.clone()))
    }
}

/// One chosen peer in a [`Selection`], with its rank and recommended concurrency (SPEC §5.1, §4.5).
///
/// (`peer_id` re-uses `dig_nat::PeerId`, which is not `serde::Serialize`; render it with
/// [`PeerId::to_hex`] for a machine-consumable surface, as [`crate::observe`] does.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedPeer {
    /// The chosen peer (transport-verified identity).
    pub peer_id: PeerId,
    /// Rank, `0` = best.
    pub rank: u32,
    /// Recommended concurrent ranges for this peer — its remaining headroom below its learned
    /// saturation point (SPEC §4.1). Always `>= 1` for a selected peer.
    pub max_concurrency: u32,
    /// `true` if chosen for exploration (SPEC §4.4-E), not proven quality.
    pub exploratory: bool,
}

/// The ranked chosen subset returned by `select` / `rebalance` (SPEC §5.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// The chosen peers, ordered best-first (index 0 has `rank == 0`).
    pub peers: Vec<SelectedPeer>,
}

impl Selection {
    /// An empty selection (no candidates worth using / no candidates offered).
    pub fn empty() -> Self {
        Selection { peers: Vec::new() }
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The number of chosen peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// The best (rank 0) chosen peer, if any.
    pub fn best(&self) -> Option<&SelectedPeer> {
        self.peers.first()
    }
}

/// The granularity of a measured outcome (SPEC §5.2, §6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// A single byte-range transfer, identified by its plan index + byte extent (SPEC §6.5).
    Range {
        /// The range index in `dig-download`'s plan.
        index: usize,
        /// The range's start offset within the resource.
        offset: u64,
        /// The range's byte length.
        length: u64,
    },
    /// A whole-request outcome — used for aggregate request-latency (P99) learning (SPEC §4.4-C).
    Request {
        /// The total resource length transferred.
        total_length: u64,
    },
}

/// The measured result of a transfer attempt (SPEC §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeResult {
    /// The transfer succeeded (and, for a range, passed `dig-download`'s merkle verification).
    Success,
    /// The transfer failed. `reason` classifies it; `VerificationFailed` is a **hard** signal.
    Failure {
        /// Why the transfer failed.
        reason: FailureReason,
    },
    /// The transfer was interrupted partway (a dropped range refetched elsewhere). `bytes_before`
    /// is what transferred before the interruption. Counts as a (soft) reliability failure.
    Interrupted {
        /// Bytes transferred before the interruption.
        bytes_before: u64,
    },
}

/// Why a transfer failed (SPEC §5.2). Additive: consumers ignore unknown variants (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// The peer did not respond / stalled within the deadline.
    Timeout,
    /// A transport-level error (connection reset, mux stream error).
    Transport,
    /// The peer reported it does not have the content (a stale provider hint).
    Unavailable,
    /// The bytes failed `dig-download`'s per-range merkle/decryption verification — a **hard**
    /// signal that the source is bad or hostile (SPEC §3.4, §6.3, §9.4).
    VerificationFailed,
    /// The transfer was cancelled by the host (not the peer's fault; not a strong penalty).
    Cancelled,
    /// Any other failure.
    Other,
}

impl FailureReason {
    /// Whether this is a **hard** failure (a bad/hostile source), which penalizes reliability more
    /// sharply and can drive the peer below cold peers (SPEC §3.4, §6.3, §9.4).
    pub fn is_hard(self) -> bool {
        matches!(self, FailureReason::VerificationFailed)
    }

    /// Whether this failure should be attributed to the *peer* at all. A host-initiated cancel is
    /// not the peer's fault, so it does not penalize reliability (SPEC §6.2 pause-is-not-a-failure
    /// spirit, applied to an explicit cancel).
    pub fn blames_peer(self) -> bool {
        !matches!(self, FailureReason::Cancelled)
    }
}

/// One measured transfer result fed back into the models in real time (SPEC §5.2).
///
/// This is the ONLY input that moves a peer's quality model (SPEC §3, §9.2): throughput is derived
/// strictly from `bytes / duration_ms` the executor measured on the wire — never a self-reported
/// rate (SPEC §9.3). An outcome for an unknown `peer_id` upserts a cold entry first (self-healing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferOutcome {
    /// Which peer served it (transport-verified identity, SPEC §9.1).
    pub peer_id: PeerId,
    /// What was being fetched.
    pub content: ContentId,
    /// Range or whole-request granularity.
    pub kind: OutcomeKind,
    /// The measured result.
    pub result: OutcomeResult,
    /// Bytes actually transferred (measured).
    pub bytes: u64,
    /// Wall-clock the transfer took, in milliseconds (measured).
    pub duration_ms: u64,
    /// Time-to-first-byte / RTT in milliseconds, if measured.
    pub rtt_ms: Option<u64>,
    /// Unix seconds the outcome completed.
    pub at: u64,
}

impl TransferOutcome {
    /// The measured throughput in bytes/sec, or `None` when it cannot be derived (zero duration or a
    /// non-success with no meaningful bytes). Derived strictly from measured `bytes`/`duration_ms` —
    /// never a self-reported rate (SPEC §9.3).
    pub fn throughput_bps(&self) -> Option<f64> {
        if self.bytes == 0 || self.duration_ms == 0 {
            return None;
        }
        Some((self.bytes as f64) * 1000.0 / (self.duration_ms as f64))
    }

    /// Whether this outcome is a success.
    pub fn is_success(&self) -> bool {
        matches!(self.result, OutcomeResult::Success)
    }

    /// Whether this outcome is a **hard** (verification) failure (SPEC §3.4, §9.4).
    pub fn is_hard_failure(&self) -> bool {
        matches!(
            self.result,
            OutcomeResult::Failure {
                reason: FailureReason::VerificationFailed
            }
        )
    }
}

/// The still-needed ranges a `rebalance` must find replacement sources for (SPEC §5.5).
///
/// Mid-transfer, when a source drops or a range must be relocated, the executor tells the selector
/// how many ranges still need a home so it can re-rank the *current* models for a replacement subset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangePlanDelta {
    /// The plan indices still needing a source (already-done ranges are never included — SPEC §6.4).
    pub needed_ranges: Vec<usize>,
}

impl RangePlanDelta {
    /// A delta for `count` still-needed ranges by index `0..count` (a convenience for the common
    /// "N ranges remain" case).
    pub fn of_count(count: usize) -> Self {
        RangePlanDelta {
            needed_ranges: (0..count).collect(),
        }
    }

    /// A delta for an explicit set of still-needed range indices.
    pub fn of_indices(indices: impl IntoIterator<Item = usize>) -> Self {
        RangePlanDelta {
            needed_ranges: indices.into_iter().collect(),
        }
    }

    /// The number of ranges still needing a source.
    pub fn len(&self) -> usize {
        self.needed_ranges.len()
    }

    /// Whether no ranges remain.
    pub fn is_empty(&self) -> bool {
        self.needed_ranges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId::from_bytes([b; 32])
    }
    const S: [u8; 32] = [0x11; 32];

    #[test]
    fn provenance_evidence_orders_live_links_above_hints() {
        assert!(Provenance::Nat.evidence() > Provenance::Gossip.evidence());
        assert!(Provenance::Gossip.evidence() > Provenance::Dht.evidence());
        assert!(Provenance::Dht.evidence() > Provenance::Pex.evidence());
        assert!(Provenance::Pex.evidence() > Provenance::Manual.evidence());
    }

    #[test]
    fn content_request_clamps_parallelism_to_at_least_one() {
        let r = ContentRequest::new(ContentId::store(S), 0);
        assert_eq!(r.effective_parallelism(), 1);
        let r = ContentRequest::new(ContentId::store(S), 5);
        assert_eq!(r.effective_parallelism(), 5);
    }

    #[test]
    fn candidate_from_provider_record_round_trips_peer_id() {
        // Built with `dig-dht`'s OWN `PeerId` type (its transitive `dig-nat` version), exactly as a
        // real DHT producer would — proving `from_provider_record` decodes the wire hex correctly
        // even when the producer and this crate resolve different `dig-nat` majors (SPEC §7.1, §11).
        let rec = ProviderRecord::new(
            &dig_dht::ContentId::store(S).to_key(),
            &dig_dht::PeerId::from_bytes([7; 32]),
            vec![CandidateAddr::direct("203.0.113.7", 9444)],
            1000,
        );
        let cand = Candidate::from_provider_record(&rec).unwrap();
        assert_eq!(cand.peer_id, pid(7));
        assert_eq!(cand.addresses.len(), 1);
    }

    #[test]
    fn throughput_derived_only_from_measured_bytes_and_duration() {
        let o = TransferOutcome {
            peer_id: pid(1),
            content: ContentId::store(S),
            kind: OutcomeKind::Range {
                index: 0,
                offset: 0,
                length: 1000,
            },
            result: OutcomeResult::Success,
            bytes: 1000,
            duration_ms: 1000,
            rtt_ms: Some(20),
            at: 5,
        };
        assert_eq!(o.throughput_bps(), Some(1000.0));
        assert!(o.is_success());
        assert!(!o.is_hard_failure());
    }

    #[test]
    fn zero_duration_or_zero_bytes_has_no_throughput() {
        let mut o = TransferOutcome {
            peer_id: pid(1),
            content: ContentId::store(S),
            kind: OutcomeKind::Request { total_length: 0 },
            result: OutcomeResult::Success,
            bytes: 0,
            duration_ms: 1000,
            rtt_ms: None,
            at: 1,
        };
        assert_eq!(o.throughput_bps(), None);
        o.bytes = 1000;
        o.duration_ms = 0;
        assert_eq!(o.throughput_bps(), None);
    }

    #[test]
    fn verification_failed_is_hard_and_blames_peer() {
        assert!(FailureReason::VerificationFailed.is_hard());
        assert!(FailureReason::VerificationFailed.blames_peer());
        assert!(!FailureReason::Timeout.is_hard());
        assert!(!FailureReason::Cancelled.blames_peer());
        assert!(FailureReason::Timeout.blames_peer());
    }

    #[test]
    fn range_plan_delta_constructors() {
        assert_eq!(RangePlanDelta::of_count(3).needed_ranges, vec![0, 1, 2]);
        assert_eq!(RangePlanDelta::of_indices([4, 9]).needed_ranges, vec![4, 9]);
        assert!(RangePlanDelta::default().is_empty());
        assert_eq!(RangePlanDelta::of_count(2).len(), 2);
    }

    #[test]
    fn selection_helpers() {
        let mut s = Selection::empty();
        assert!(s.is_empty());
        assert!(s.best().is_none());
        s.peers.push(SelectedPeer {
            peer_id: pid(1),
            rank: 0,
            max_concurrency: 2,
            exploratory: false,
        });
        assert_eq!(s.len(), 1);
        assert_eq!(s.best().unwrap().peer_id, pid(1));
    }
}
