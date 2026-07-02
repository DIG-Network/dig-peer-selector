# DIG Peer Selector — Self-Optimizing Peer-Selection Specification

**Status:** Normative · **API version:** `1` · **Crate:** `dig-peer-selector`

This document is the authoritative contract for `dig-peer-selector`, the self-optimizing
peer-selection middleware of the DIG Node. An independent implementation built from this document
alone MUST behave interchangeably with the reference crate: given the same registry feed and the
same stream of measured outcomes, it MUST make selection decisions with the same invariant
properties (it need not reproduce the exact numeric scores — §1.4).

The selector is a pure **decision + learning** layer. It sits between `dig-download` (the executor
that fetches bytes) and the peer-discovery layers (`dig-dht`, `dig-pex`/`dig-gossip`, `dig-nat`). It
answers one question — *"of these candidate peers, which subset should serve this content, and in
what order?"* — and it learns the answer from the **real, measured outcome** of every transfer it
influenced. It has **no user-facing configuration**: every tradeoff is self-tuned from observed
data.

---

## 1 · Purpose, scope & boundaries

### 1.1 What the selector is

The selector maintains a **dynamic registry** of candidate peers (fed by the discovery layers),
attaches to each peer a **learned quality model** derived from real download outcomes, and exposes a
**closed feedback loop**:

1. `dig-download` (via the node) asks the selector to **`select`** the best peer subset for a
   content request.
2. `dig-download` executes the multi-source byte-range transfer over `dig-nat` mTLS mux streams.
3. Every per-range and per-request outcome (throughput, latency, success/failure, which peer, which
   range) streams back into the selector via **`record_outcome`**, updating the models **in real
   time** so the next `select` — and a mid-transfer **re-balance** — is smarter.

The loop is autonomous: it improves selection with no manual tuning and no user-visible knobs.

### 1.2 What the selector is NOT (boundaries)

The selector **MUST NOT** perform, own, or re-implement any of the following — they belong to the
named crates and the selector only *reads their outputs* or *drives their choices*:

- **Discovery / the DHT lookup.** It does not query the DHT. The node calls
  `dig-dht`'s `find_providers` and hands the resulting candidates in (§7.1). ([Peer network §4c](https://docs.dig.net/docs/protocol/peer-network#dht).)
- **Topology maintenance.** It does not run the gossip peer pool or PEX; it subscribes to their
  churn to keep its registry current (§7.2). ([Peer network §4d](https://docs.dig.net/docs/protocol/peer-network#pex).)
- **Transport / NAT traversal.** It never opens a socket, a TLS session, or a mux stream. All
  node-to-node traffic is mTLS via `dig-nat`; the selector only *reads* the established connection
  class (§7.3). ([Peer network §0 dual-transport](https://docs.dig.net/docs/protocol/peer-network#dual-transport), [§2](https://docs.dig.net/docs/protocol/peer-network#nat-traversal).)
- **Byte transfer / verification / pause-resume.** It does not fetch, verify, decrypt, or persist
  ranges. `dig-download` owns the transfer, per-chunk merkle verification, and resume (§6).
- **User configuration.** It exposes **no** behavior-changing knobs (§1.5). Internal
  hyperparameters are self-tuned from observed data, never surfaced as settings.

### 1.3 Conventions & terminology

- The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be
  interpreted as in RFC 2119.
- **`peer_id`** — the mTLS peer identity, `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`, 32
  bytes, rendered as 64 lower-case hex on every text surface. This is the SAME identity across
  `dig-nat`, `dig-gossip`, `dig-dht`, and `dig-pex`; the selector re-uses it verbatim and **MUST
  NOT** invent its own peer key. ([Peer network §1](https://docs.dig.net/docs/protocol/peer-network#peer-identity).)
- **Connection class** — the `dig-nat` traversal tier that established a peer link: `Direct`,
  `Upnp`, `NatPmp`, `Pcp`, `HolePunch`, `Relayed` (`dig_nat::TraversalKind`). Per the
  relay-last-fallback invariant, `Relayed` means the relay carries every byte; every other class is
  a peer-to-peer data path. ([Peer network §10](https://docs.dig.net/docs/protocol/peer-network#invariant).)
- **Peer class** — an equivalence bucket the selector learns saturation behavior *per*, keyed by
  the coarse connection-path category (§4.1). NOT the same as the raw connection class.
- **Candidate** — a peer offered as a possible source for a specific content request (from
  `dig-dht` providers, filtered/ordered against the registry).
- **Outcome** — a *measured* result of a real transfer attempt (a range or a whole request): the
  only input that moves a peer's quality model (§3, §9.2). Advertised or self-reported capacity is
  **not** an outcome and **MUST NOT** move the model.
- **Registry** — the selector's live map of `peer_id → PeerEntry` (§2).

### 1.4 Behavioral conformance, not numeric conformance

This spec fixes the selector's **API shapes**, its **inputs**, and the **invariant properties** its
learning and scoring MUST satisfy (§4.4, §12). It deliberately does **not** fix a scoring *formula*,
a decay *constant*, or a saturation *threshold* — those are learned. An implementation conforms iff:

- its public API matches §5 exactly (the frozen surface); and
- its behavior satisfies every invariant in §4.4 and passes the conformance harness in §8.

Two conforming implementations MAY assign different numeric scores to the same peer; they MUST reach
the same *qualitative* decisions the invariants describe (converge to fast/reliable peers, spread
load off a saturating peer, adapt when a peer degrades).

### 1.5 No user-facing configuration

The selector exposes **no** settings that change its selection behavior. `SelectorConfig` (§5.6) MAY
carry pure wiring (clock source, registry capacity bound, an RNG seed for deterministic tests) but
**MUST NOT** expose scoring weights, decay constants, saturation limits, or a relayed penalty as
tunables. Any such quantity is a learned internal state, not a knob. A build that exposes a scoring
knob to the user does not conform.

---

## 2 · The dynamic peer registry

### 2.1 The peer entry

The registry maps `peer_id` → **`PeerEntry`**. An entry carries identity, reachability, and the
learned quality model. Its logical shape (field names are the API contract; the in-memory type MAY
add private fields):

```text
PeerEntry {
  peer_id:           PeerId,                 // SHA-256(TLS SPKI DER); the registry key
  addresses:         Vec<CandidateAddr>,     // dial candidates, byte-compatible with dig-dht/L7
  connection_class:  Option<TraversalKind>,  // the dig-nat tier of the live link, if connected
  provenance:        Provenance,             // how this peer entered the registry (§2.3)
  quality:           PeerQuality,            // the learned model (§3) — MEASURED-only
  first_seen:        u64,                    // unix seconds, when first registered
  last_outcome_at:   Option<u64>,            // unix seconds of the most recent measured outcome
}
```

- `addresses` uses the `CandidateAddr { host, port, kind }` shape (kinds
  `direct|mapped|reflexive|relay`) **byte-compatible** with `dig-dht` provider records and the L7
  `dig.getPeers` address shape ([Peer network §7](https://docs.dig.net/docs/protocol/peer-network#peer-rpc)). The selector MUST sort candidate addresses
  most-direct-first by `kind` rank when it needs a preferred dial target; it MUST NOT assume wire
  order.
- `connection_class` is **observational only** — read from `dig-nat` (`PeerConnection::method` /
  `NatPeerConnection::method()`) for a currently-connected peer, `None` otherwise. It seeds
  relayed-penalty *priors* but is subordinate to measured outcomes (§3.3, §4.2).
- `quality` starts **cold** (§3.5) for a newly-registered peer and is refined only by
  `record_outcome`.

### 2.2 Provenance

`Provenance` records how the peer entered the registry. It is a hint about *trust of the address*,
never a substitute for a measured outcome (§9.1):

```text
Provenance = Dht | Gossip | Pex | Nat | Manual
```

| Token | Meaning |
|---|---|
| `Dht` | Learned as a `dig-dht` provider record for some content (§7.1). |
| `Gossip` | Present in the `dig-gossip` connected pool (a live mTLS link) (§7.2). |
| `Pex` | Learned via peer exchange — a HINT only, quality unknown until measured (§7.2, §9.1). |
| `Nat` | A connection whose class `dig-nat` reported directly. |
| `Manual` | Injected by the host for testing / bootstrap. |

A peer MAY be known via several provenances; the registry keeps the strongest-evidence one and MAY
retain the set. Provenance MUST NOT by itself raise a peer's quality score — only measured outcomes
do (§9).

### 2.3 Feeding the registry (join / leave)

The registry is **fed, not self-discovered**. Two feeds keep it live:

1. **Gossip pool churn (the topology feed).** The host subscribes to
   `dig-gossip::GossipHandle::subscribe_pool_events()` and forwards each `PoolEvent` to the selector
   via `on_pool_event` (§5.4):
   - `PoolEvent::PeerAdded { peer_id, addr }` → the selector **upserts** a registry entry
     (provenance `Gossip`), preserving any existing learned `quality` (a reconnecting peer keeps its
     history — §2.4).
   - `PoolEvent::PeerRemoved { peer_id, reason }` → the peer is marked **disconnected**; its entry
     and its learned `quality` are **retained** (not deleted) so a later reconnect resumes from
     history, subject to §2.5 eviction. `reason` (`Disconnected|Dead|Banned`) is recorded; `Banned`
     SHOULD make the peer ineligible for selection until re-added.
   The host MAY additionally seed the registry from a `connected_pool_peers()` snapshot at startup.

2. **DHT providers (the candidate feed).** On each content want the host passes `dig-dht`
   `find_providers` results into `select` as `candidates` (§5.1); a candidate not yet in the registry
   is upserted (provenance `Dht`) with a cold quality model, so its first selection is exploratory
   (§4.4-E) and its first outcome starts its history.

`dig-nat` connection classes are attached as connections are established (`on_connection_class`,
§5.4).

### 2.4 Identity is measured, not asserted

The registry key is always the transport-verified `peer_id`. The selector MUST NOT trust a
`peer_id`, address, or class asserted in any *message payload*; the only authoritative source of a
peer's identity is the mTLS handshake that `dig-nat` completed (§9.1). Addresses arriving via
`dig-pex`/DHT are dial *hints* — proven only when a transfer over them yields a measured outcome.

### 2.5 Registry bounds & eviction

The registry MUST be bounded (a capacity in `SelectorConfig`, a pure resource limit, not a behavior
knob). When over capacity the selector evicts the **lowest-value** entries first, where value
combines staleness (`last_outcome_at` age) and learned quality, PREFERRING never to evict a
currently-connected peer or one with a range in flight. Eviction of a peer's entry discards its
learned quality; a re-learned peer starts cold again. Eviction MUST NOT be observable as a behavior
knob.

**The capacity bound is a HARD limit, not merely a preference.** A dispatch whose outcome never
arrives (the peer went silent post-dispatch) MUST NOT be able to pin an entry as permanently
unevictable: an unsettled `in_flight` count is reclaimed after a bounded dispatch TTL (§5.3), and if,
after reclamation, every remaining entry is still connected or in-flight, capacity enforcement MUST
fall back to evicting the lowest-value **non-connected** entry regardless of its `in_flight` count. A
currently-connected live link is the only thing eviction may never touch; everything else is subject
to the bound. This closes the resource-bound bypass an attacker could otherwise trigger by feeding a
stream of unique cold `peer_id`s that are dispatched to (via exploration / anti-starvation forced
coverage, §4.4-E) and then never report an outcome.

---

## 3 · The per-peer capacity & quality model

### 3.1 What is learned (measured-only)

`PeerQuality` is refined **only** from measured outcomes (§9.2). It captures at least:

```text
PeerQuality {
  throughput:   Estimate,   // achievable bytes/sec, learned (§3.2)
  rtt:          Estimate,   // round-trip / time-to-first-byte latency, learned (§3.2)
  reliability:  Estimate,   // success probability in [0,1], learned (§3.4)
  samples:      u64,        // count of measured outcomes folded in (confidence)
  in_flight:    u32,        // ranges currently assigned to this peer (live, not learned)
}
```

`throughput` and `rtt` are the peer's **observed capacity**. Advertised or self-reported capacity
(e.g. a peer claiming a bandwidth in a message) MUST NOT be folded into these estimates — **observed
capacity always overrides advertised** (§9.3). A peer that *claims* to be fast but *measures* slow
is treated as slow.

### 3.2 The estimator (normative properties, not a constant)

Each of `throughput` and `rtt` is a **recency-weighted** estimate over the peer's outcome stream. An
implementation MAY use an EWMA, a decaying reservoir, a windowed quantile, or any estimator that
satisfies ALL of the following normative properties:

- **P-recency.** A more recent outcome influences the estimate at least as much as an older one; as
  outcomes accumulate, ancient samples' influence decays toward zero.
- **P-monotone-convergence.** Under a *stationary* outcome stream (a peer that consistently delivers
  throughput `T`), the estimate converges toward `T` and stays within a bounded neighborhood of it.
- **P-responsive-degradation.** When a peer's true performance drops from `T_high` to `T_low` and
  stays there, the estimate converges toward `T_low` within a bounded number of subsequent outcomes
  — it MUST NOT stay pinned near `T_high` (§4.4-D).
- **P-volatility-tracking.** The estimator's effective memory (how fast it decays) is **adaptive to
  observed volatility**, not a fixed policy constant: a peer whose outcomes are steady is smoothed
  over a longer effective window; a peer whose outcomes swing widely decays faster so a stale-but-once-good
  reading falls off. The decay is *derived from the data*, per §4.3.

The estimator carries enough state to expose a **confidence** (via `samples` and, SHOULD, an
observed variance) so the scorer can distinguish a well-measured peer from a barely-sampled one
(§4.4-E).

### 3.3 Connection-class prior

The `connection_class` seeds a **prior** on a cold peer only: a `Relayed` peer starts with a
throughput/latency prior no better than a direct peer's, so it is not preferred before it is
measured. The prior is a starting point, not a cap: once measured, the peer's estimate is driven by
outcomes, so a relayed peer that measures fast is used and a direct peer that measures slow is
demoted. The magnitude of the relayed prior is itself learned (§4.2), not a fixed constant.

### 3.4 Reliability

`reliability` is a recency-weighted success rate over `{success, failure}` outcomes (a
timeout/interruption/verification-failure is a failure — §6.2). It satisfies the same P-recency and
P-responsive-degradation properties: a peer that starts failing MUST see its reliability fall, and a
recovering peer MUST see it rise. A verification failure (a peer served bytes that failed the merkle
check — §6.3) is a **hard** failure and SHOULD penalize reliability more sharply than a transport
timeout, because it may indicate a bad or hostile source.

### 3.5 The cold state & exploration

A newly-registered peer has `samples == 0` and an **unknown** quality: neither optimistic nor
pessimistic, but *uncertain*. The scorer MUST give cold peers a bounded **exploration** allowance so
they get measured (§4.4-E) — the selector cannot learn a peer it never tries — while never letting
unmeasured peers crowd out proven fast ones for the bulk of a transfer.

---

## 4 · The autonomous scoring function

### 4.1 Learned saturation point (per peer class)

The selector learns, **per peer class**, each peer's **saturation point** — the number of concurrent
in-flight ranges beyond which that peer's *measured* throughput stops rising (and then degrades). It
MUST:

- estimate saturation from the observed relationship between a peer's `in_flight` at dispatch time
  and the throughput the resulting outcomes measured (more concurrency that yields no more aggregate
  throughput, or lower per-range throughput, signals saturation);
- stop assigning a peer additional concurrent ranges once it is at or past its learned saturation
  point, spilling the excess to the next-best peer (§4.4-B, the anti-thundering-herd rule);
- generalize across peers of the same **class** (peers reached by a similar connection path share a
  saturation prior) so a *new* peer of a known class inherits a sane concurrency prior before it is
  individually measured, then specializes as its own outcomes arrive.

The saturation point is learned, not a fixed constant; it MUST adapt if a peer's capacity changes.

### 4.2 Adaptive relayed-connection penalty

A relayed link often (not always) has lower throughput and higher latency, and consumes shared relay
bandwidth. The selector learns a **relayed penalty** rather than hardcoding one:

- the penalty is derived from the **observed frequency and real performance impact** of relayed
  transfers — how often relayed peers are the only/relevant option, and how their *measured*
  throughput/reliability compares to non-relayed peers;
- a relayed peer that consistently measures fast MUST NOT be over-penalized (its measured quality
  dominates); a relayed peer that consistently measures slow MUST be de-prioritized accordingly;
- the penalty tracks the environment: in a network where relayed links measure nearly as well as
  direct, the learned penalty shrinks; where they measure much worse, it grows.

This is a *learned prior/adjustment*, subordinate to per-peer measured quality (§3.3). It MUST NOT be
exposed as a user knob.

### 4.3 Observed-volatility-driven decay

The recency-weighting/decay of each peer's quality (§3.2 P-volatility-tracking) is driven by that
peer's **observed volatility**, not a baked-in policy constant:

- a peer whose recent outcomes are consistent is decayed slowly (its history is trustworthy);
- a peer whose recent outcomes swing widely is decayed quickly (a reading from an hour ago is a poor
  predictor), so *"was fast an hour ago but is now degraded"* is reflected promptly (§4.4-D).

An implementation MUST derive the effective decay from the data (e.g. from the estimate's residual
variance / an observed change-rate); it MUST NOT expose a single global decay constant as policy.

### 4.4 Optimization objective & invariants

The scorer's objective is, jointly:

- **minimize P99 request latency** across the node's download requests (make the *slowest* requests
  faster — not merely the median), and
- **avoid thundering-herd** collapse on high-capacity peers (do not route so much concurrency to the
  one fast peer that it saturates and its throughput collapses).

An implementation's scoring and dispatch MUST satisfy these frozen invariants:

| ID | Invariant |
|---|---|
| **A · Convergence** | Under a stationary topology, repeated `select`+`record_outcome` cycles converge to preferring the fast, reliable peers: a peer with strictly higher measured throughput and reliability is ranked ahead of a strictly worse one (all else equal), and receives a larger share of ranges over time. |
| **B · Load-spread / anti-herd** | The selector MUST NOT pile unbounded concurrency on a single high-capacity peer. Once a peer reaches its learned saturation point (§4.1) it receives no additional concurrent ranges; further demand spreads to the next-best peers. Sending *every* range to the single fastest peer is a conformance failure even if that peer has the best point estimate. |
| **C · P99 orientation** | Given a set of ranges and candidates, the chosen subset+assignment MUST reduce the *expected completion time of the whole request* (bounded by its slowest range), not just pick the single best peer. A peer likely to leave a range straggling (low reliability / near saturation / high tail latency) MUST be down-weighted for tail-sensitive assignment even if its median throughput is high. |
| **D · Degradation adaptation** | When a peer's measured performance degrades and stays degraded, its rank MUST fall within a bounded number of subsequent outcomes (§3.2 P-responsive-degradation, §4.3); a peer that recovers MUST rise again. The selector MUST NOT keep routing to a peer that has been consistently failing/slow on stale history. |
| **E · Exploration** | Cold (unmeasured) peers MUST get bounded exploratory selection so they acquire outcomes, without unmeasured peers displacing proven fast peers for the bulk of a transfer. A network of all-cold peers MUST still make progress (every candidate is tried). |
| **F · Determinism (testability)** | Given the same config (incl. RNG seed), the same registry state, and the same ordered outcome stream, `select` MUST produce the same ranking. Any randomness (exploration tie-breaks) MUST be seedable so §8 tests are reproducible. |
| **G · Bounded work** | `select` and `record_outcome` MUST run in time bounded by the candidate/registry size (no unbounded recomputation); the models are updated incrementally per outcome. |

### 4.5 Ranking output

`select` returns a **ranked subset** — an ordered list of chosen peers with, per peer, a recommended
concurrency (its remaining headroom below its learned saturation point) so `dig-download` knows both
*who* and *how many concurrent ranges each*. The subset size is bounded by the request's requested
parallelism (§5.1) and by how many candidates are worth using (a low-quality tail MAY be omitted).
The ranking MUST be stable under §4.4-F.

---

## 5 · Public API contract

The frozen public surface (version `1`). Types are given in normative logical form; the crate's
concrete Rust signatures MUST match these shapes (names, parameters, return semantics). All identity
types (`PeerId`, `CandidateAddr`, `TraversalKind`, `ContentId`, `ProviderRecord`) are **re-used from
the sibling crates** (`dig-nat`, `dig-dht`) — the selector MUST NOT define parallel copies.

### 5.1 `select` — rank a candidate set for a request

```text
fn select(&self, req: &ContentRequest, candidates: &[Candidate]) -> Selection
```

- **`req: ContentRequest`** — what is being fetched and how:

  ```text
  ContentRequest {
    content:      ContentId,        // dig-dht ContentId: Store | Root(capsule) | Resource
    total_length: Option<u64>,      // resource ciphertext length if known (from availability)
    range_count:  Option<usize>,    // planned number of ranges, if known
    parallelism:  usize,            // how many parallel sources the caller wants (>= 1)
  }
  ```

- **`candidates: &[Candidate]`** — the population to rank, typically the `dig-dht` `find_providers`
  result mapped in. A `Candidate` carries at least `peer_id` and `addresses` (from
  `ProviderRecord`), and MAY carry a known `connection_class`. Candidates not yet in the registry
  are upserted (cold) as a side effect (§2.3), so `select` MAY take `&self` with interior mutability
  or `&mut self` — the crate fixes which; the *semantics* are: selecting a fresh candidate registers
  it.
- **returns `Selection`** — the ranked chosen subset:

  ```text
  Selection { peers: Vec<SelectedPeer> }
  SelectedPeer {
    peer_id:            PeerId,
    rank:               u32,      // 0 = best
    max_concurrency:    u32,      // recommended concurrent ranges for this peer (§4.1 headroom)
    exploratory:        bool,     // true if chosen for exploration (§4.4-E), not proven quality
  }
  ```

- **Semantics.** `select` MUST satisfy §4.4. It MUST NOT block on I/O (pure, in-memory). An empty
  candidate set yields an empty `Selection` (the node handles "no providers"). `select` never
  mutates a peer's *learned quality* — only `record_outcome` does.

### 5.2 `record_outcome` — feed a measured result back (real time)

```text
fn record_outcome(&self, outcome: &TransferOutcome)
```

- **`TransferOutcome`** — one measured result, at either granularity:

  ```text
  TransferOutcome {
    peer_id:      PeerId,           // which peer (transport-verified, §9.1)
    content:      ContentId,        // what was being fetched
    kind:         OutcomeKind,      // Range { .. } | Request { .. }
    result:       OutcomeResult,    // Success | Failure { reason } | Interrupted { .. }
    bytes:        u64,              // bytes actually transferred (measured)
    duration_ms:  u64,             // wall-clock the transfer took (measured)
    rtt_ms:       Option<u64>,      // time-to-first-byte / RTT if measured
    at:           u64,              // unix seconds the outcome completed
  }
  OutcomeKind    = Range { index: usize, offset: u64, length: u64 } | Request { total_length: u64 }
  OutcomeResult  = Success | Failure { reason: FailureReason } | Interrupted { bytes_before: u64 }
  FailureReason  = Timeout | Transport | Unavailable | VerificationFailed | Cancelled | Other
  ```

- **Semantics.** `record_outcome` folds the measured throughput (`bytes / duration_ms`), latency
  (`rtt_ms`/`duration_ms`), and success/failure into the peer's `PeerQuality` **immediately**, per
  the estimator properties (§3.2, §3.4) and updates the peer's saturation/volatility learning (§4.1,
  §4.3). It MUST run in real time (called per range as ranges complete mid-transfer) so an in-flight
  download can be re-balanced (§5.5). Outcomes for an unknown `peer_id` upsert a cold entry first
  (self-healing). `VerificationFailed` is a hard failure (§3.4). `record_outcome` MUST NOT trust any
  self-reported throughput — it derives throughput only from `bytes` and `duration_ms` it is given by
  the executor (§9.3).

### 5.3 In-flight accounting

The selector tracks `in_flight` per peer (§3.1) to apply saturation (§4.1). The executor MUST inform
the selector when a range is **dispatched** to a peer and when it **settles** (success/failure);
this MAY be implicit (a `SelectedPeer` in a `Selection` is counted dispatched, and the matching
`record_outcome` decrements) or explicit via `on_dispatch(peer_id, range)` / the settling
`record_outcome`. The crate fixes the mechanism; the *invariant* is that `in_flight` reflects reality
so §4.4-B holds.

**Dispatches are TTL-reclaimed, not just decremented.** A dispatch bump MAY exceed the count a
matching `record_outcome` releases (e.g. a peer is dispatched `max_concurrency` ranges' worth of
headroom in one `select` but only ever reports outcomes one at a time, or an outcome never arrives at
all because the peer went silent). The selector MUST NOT let such an imbalance leave `in_flight`
permanently stuck above `0`: it stamps the wall-clock time `in_flight` last rose from `0` and, on each
`select`/`rebalance`, reclaims (zeros) `in_flight` for any entry whose dispatch has aged past a bounded
TTL without settling. This is what keeps §2.5's capacity bound genuinely enforceable rather than
gameable by an attacker who dispatches to a peer and then never reports back.

### 5.4 Registry-feed hooks

```text
fn on_pool_event(&self, event: &PoolEvent)              // dig-gossip churn (§2.3, §7.2)
fn on_connection_class(&self, peer: &PeerId, class: TraversalKind)  // dig-nat class (§7.3)
fn upsert_candidate(&self, candidate: &Candidate)        // manual/seed feed (§2.3)
fn remove_peer(&self, peer: &PeerId)                      // explicit removal (rare; churn usually drives this)
```

- `on_pool_event` consumes the gossip churn event (`PeerAdded`/`PeerRemoved`) with the **exact shape**
  of `dig_gossip::PoolEvent` (`PeerAdded { peer_id, addr }`, `PeerRemoved { peer_id, reason }`, over
  the re-used `dig_nat::PeerId` and a `PoolRemovalReason` of `Disconnected|Dead|Banned`). The shape is
  **byte-identical** so a host maps a `dig_gossip::PoolEvent` to it 1:1.
  **Implementation note (binding deviation, recorded per the spec-with-code rule §10):** the reference
  crate **mirrors** this event type locally rather than `use`-ing `dig-gossip` directly. `dig-gossip`
  pulls the entire chia-protocol/consensus/TLS stack into what is a pure decision layer, and its
  published git tip does not currently compile as a dependency (it lags the upstream `chia-*` crate
  versions), which would both bloat and *break* this crate's build — contradicting this spec's own
  dependency-minimalism principle (§1, §11) and the `dig-dht`/`dig-pex` precedent that deliberately
  avoid `dig-gossip`. The mirrored type is field-for-field identical, exactly as `dig-pex` mirrors the
  L7 address shape "rather than pulling those crates in"; when `dig-gossip` is published to crates.io
  with a compiling tip it MAY be replaced by a direct re-export with no field/variant change. The
  contract (the shape the host feeds in) is unchanged; only the *source* of the type differs.
- `on_connection_class` attaches / updates a live peer's `connection_class` (§2.1) from
  `dig_nat::TraversalKind`.

### 5.5 The re-balance query

```text
fn rebalance(&self, req: &ContentRequest, active: &[PeerId], need: &RangePlanDelta) -> Selection
```

Mid-transfer, when a source drops or a range must be relocated (`dig-download`'s relocate path, §6),
the executor calls `rebalance` to re-query the *current* (freshly-learned) models for a replacement
subset for the still-needed ranges, excluding/`de-ranking` the `active` peers already saturated and
the peer that just failed. `rebalance` MUST reflect every `record_outcome` received so far in the
transfer (it is not a cached copy of the original `select`). It obeys the same invariants (§4.4).

### 5.6 `SelectorConfig` (wiring only)

```text
SelectorConfig {
  clock:            ClockSource,   // injectable clock (tests drive time deterministically)
  rng_seed:         Option<u64>,   // seed for exploration tie-breaks (§4.4-F)
  registry_capacity: usize,        // resource bound (§2.5), NOT a behavior knob
}
```

`SelectorConfig` MUST NOT carry scoring weights, decay constants, saturation limits, or a relayed
penalty (§1.5). Adding such a field is a conformance failure.

### 5.7 Observability (read-only, non-behavioral)

The selector MAY expose read-only introspection for debugging/metrics — e.g. a snapshot of a peer's
learned `PeerQuality`, the current registry size, learned saturation/penalty values, and the size of
any internal per-peer bookkeeping the engine keeps outside the registry (e.g. anti-starvation /
dispatch-attribution side maps). These are **observability only**: reading or logging them MUST NOT
change selection behavior, and they are not configuration. This satisfies the ecosystem
"agent-friendly / machine-consumable" requirement without introducing a knob.

**No side map may outlive a peer's registry membership (#179 finding 2).** Any per-peer bookkeeping
the engine keeps *outside* the registry (e.g. the last-selected epoch for anti-starvation coverage,
or dispatch-attribution context keyed by peer) MUST be pruned for a `peer_id` no later than the same
operation that removes it from the registry (capacity eviction or explicit removal, §2.5). Such a
side map's size MUST track the live registry population, not the cumulative count of distinct
`peer_id`s ever fed — otherwise the registry's own capacity bound (§2.5) protects nothing, since an
attacker feeding a continuous stream of unique cold `peer_id`s would still grow unbounded state
elsewhere in the selector.

---

## 6 · The feedback-loop contract with `dig-download`

The selector and `dig-download` form the tight `select → execute → record_outcome → rebalance` loop.
This section binds the selector's contract to `dig-download`'s exact outcome, event, and resume model.

### 6.1 Who drives peer choice

`dig-download` today picks a source with an internal least-loaded heuristic (`pick_source`). Under
this contract the **selector drives that choice**: `dig-download` obtains its source subset (and each
source's recommended concurrency) from `select`/`rebalance` instead of the built-in heuristic. The
selector is the decision authority; `dig-download` remains the executor. (The integration adds the
selector as the source-selection seam in `dig-download`; the selector crate itself defines the
contract, not the wiring.)

### 6.2 Outcomes stream back during the transfer

`dig-download` emits a `DownloadEvent` stream as the transfer runs. The host adapter MUST translate
each relevant event into a `record_outcome` (or in-flight update) **as it happens**, so the models
update mid-transfer:

| `dig-download` `DownloadEvent` | Selector call | Mapping |
|---|---|---|
| `RangeCompleted { range, provider, progress }` | `record_outcome` | `kind: Range { index: range, .. }`, `result: Success`, `peer_id = provider`, `bytes`/`duration_ms` from the range's measured transfer, decrement `in_flight`. |
| `RangeFailed { range, provider, reason }` | `record_outcome` | `result: Failure { reason }` (map `reason` → `FailureReason`; a verify/integrity failure → `VerificationFailed`), decrement `in_flight`. This is the failure the selector LEARNS from (§3.4) and re-routes around. |
| `ProvidersRefreshed { providers }` | (registry feed) | New providers from `dig-download`'s relocate re-query become candidates on the next `select`/`rebalance`. |
| `Paused` / `Resumed` | (in-flight only) | On pause, in-flight ranges are no longer dispatched; the selector's learned quality is UNCHANGED (a pause is not a peer failure). |
| `Completed { total_length }` | `record_outcome` (optional) | An aggregate `Request` outcome MAY be recorded for whole-request latency learning (P99, §4.4-C). |
| `Failed { reason }` | (no quality change beyond the per-range failures already recorded) | The request-level failure is composed of the per-range outcomes already learned. |

A range's *measured* `bytes`/`duration_ms`/`rtt_ms` are what the executor observed on the wire — the
selector MUST use those, never a peer's advertised rate (§9.3).

### 6.3 Per-range integrity failures are hard signals

`dig-download` verifies every range against the chain-anchored merkle root before accepting it
([Peer network §9 integrity](https://docs.dig.net/docs/protocol/peer-network#range-integrity)). A range that fails verification (bad chunk length, failed
inclusion proof, or a decryption-tag failure) is a `RangeFailed` with an integrity reason; the
adapter MUST map it to `FailureReason::VerificationFailed`, which the selector treats as a **hard**
reliability penalty (§3.4). A peer that repeatedly serves unverifiable bytes MUST be driven toward
the bottom of the ranking (potentially below cold peers) — a bad source is worse than an unknown one.

### 6.4 Pause / resume alignment

`dig-download` resumes **per range**: its `DownloadState { done_ranges, chunk_lens, root, .. }`
records which ranges are already verified so a resume re-fetches only the missing ones. The selector's
contract with resume:

- **Learned quality survives a pause/resume and the process** only if the host persists it; the
  selector's in-memory quality is NOT part of `DownloadState`. A resume after a restart begins with
  the registry as re-fed by the discovery layers; peers re-acquire quality from the resumed transfer's
  outcomes. (The selector MAY expose a snapshot for the host to persist, but persistence is the
  host's choice — the selector defines no on-disk format in version 1.)
- On resume, `dig-download` calls `select`/`rebalance` for the **remaining** ranges only; the
  selector MUST rank against whatever registry/quality it currently holds. Ranges already in
  `done_ranges` are never re-selected (the executor does not ask for them).
- A pause is **not** a failure signal (§6.2) — the selector MUST NOT penalize a peer for a
  user-initiated pause.

### 6.5 Range identity

A range is identified to the selector by its index and byte extent (`OutcomeKind::Range { index,
offset, length }`), matching `dig-download`'s range plan (chunk-aligned, keyed by index + offset).
The selector does not need the chunk merkle layout; it needs only the identity to attribute an
outcome to a range and a peer.

---

## 7 · Integration bindings

All bindings are **read-only inputs** to the selector or **choices the selector drives**; the
selector opens no transport and owns no discovery (§1.2).

### 7.1 `dig-dht` — the candidate source

- The node calls `dig_dht::DhtService::find_providers(&ContentId) -> Result<Vec<ProviderRecord>, _>`
  and maps each `ProviderRecord { content_key, provider_peer_id, addresses, expires_at }` into a
  `Candidate` for `select`. The selector MUST re-use `dig_dht`'s `ContentId`, `ProviderRecord`,
  `CandidateAddr`, and `AddressKind` types (which themselves re-use `dig_nat::PeerId`) — no parallel
  definitions.
- The selector treats a provider record as an **address hint** (§9.1): the peer is proven to hold the
  content only when a transfer from it yields a `Success` outcome. An expired record
  (`now >= expires_at`) SHOULD be ignored as a candidate.
- The selector does **not** query the DHT, announce, or maintain provider records. ([Peer network §4c](https://docs.dig.net/docs/protocol/peer-network#dht).)

### 7.2 `dig-pex` / `dig-gossip` — the topology feed

- The registry is fed from the `dig-gossip` connected pool: `subscribe_pool_events()` →
  `on_pool_event` (§2.3), `connected_pool_peers()` for an initial snapshot, `pool_stats()` for
  under-connected awareness (a host MAY widen exploration when the pool is below target). The
  selector consumes the gossip churn event with the **exact shape** of `dig_gossip::PoolEvent`
  (mirrored field-for-field locally per the §5.4 binding note; the host maps `dig_gossip::PoolEvent`
  to it 1:1).
- `dig-pex`-learned peers arrive (through the gossip address book / pool) as **hints** with unknown
  quality; the selector marks provenance `Pex`/`Gossip` and treats quality as cold until measured
  (§3.5, §9.1) — exactly the dig-pex trust rule (a PEX entry is a candidate to dial and verify, never
  an authenticated fact). ([Peer network §4d](https://docs.dig.net/docs/protocol/peer-network#pex).)

### 7.3 `dig-nat` — connection class + mTLS transport

- The selector reads each connected peer's `dig_nat::TraversalKind` (`Direct`, `Upnp`, `NatPmp`,
  `Pcp`, `HolePunch`, `Relayed`) via `on_connection_class` (from `PeerConnection::method` /
  `NatPeerConnection::method()`) to seed the peer-class saturation prior (§4.1) and the relayed
  penalty prior (§4.2). `Relayed` is the only class that means the relay carries the bytes; all others
  are peer-to-peer data paths ([Peer network §10](https://docs.dig.net/docs/protocol/peer-network#invariant)).
- All transfers the selector influences ride `dig-nat` mTLS mux streams (`PeerSession::open_stream` /
  `open_range_stream`); the selector never opens one itself. `peer_id = SHA-256(TLS SPKI DER)` is the
  identity throughout (§1.3, §9.1).

### 7.4 `dig-node` (digstore) — the host

- `dig-node` constructs the selector, wires the gossip pool subscription and `dig-nat` connection
  classes into it, calls `find_providers` per content want and passes the providers to `select`, and
  runs the `select ↔ dig-download` loop (translating `DownloadEvent`s into `record_outcome` calls,
  §6.2). The selector is a dependency of the node's content-fetch path.

---

## 8 · Testability & conformance harness

The learning and scoring MUST be unit-testable with **synthetic** topologies and throughput traces —
no real network. An implementation MUST pass a harness that feeds it a simulated candidate population
and a scripted outcome stream (via `record_outcome`) and asserts the §4.4 invariants:

1. **Convergence test (A).** Feed peers with fixed distinct throughputs/reliabilities; drive repeated
   `select`+`record_outcome` cycles; assert the ranking converges to prefer the fast/reliable peers
   and that the fastest peer's *share* of ranges rises while the slowest's falls.
2. **Load-spread / anti-herd test (B).** Give one peer the highest point throughput but a low
   saturation point; drive a high-parallelism request; assert the selector caps that peer at its
   learned saturation headroom and spreads the remaining ranges to others (it does NOT send all
   ranges to the one peer even though its point estimate is best).
3. **Degradation-adaptation test (D).** Feed a peer high throughput, then flip its trace to low
   throughput / failures; assert its rank falls within a bounded number of subsequent outcomes and
   selection moves off it; then flip it back and assert it recovers.
4. **P99 test (C).** Compose a mix where a high-median peer has a heavy tail; assert the selector's
   assignment reduces whole-request completion time (bounded by the slowest range) versus a naive
   "pick the best point estimate" baseline.
5. **Exploration test (E).** Start all peers cold; assert every candidate is tried (acquires an
   outcome) and the selector still converges; assert unmeasured peers do not displace a proven fast
   peer for the bulk of a transfer.
6. **Determinism test (F).** With a fixed `rng_seed` and clock, assert identical rankings for
   identical registry state + outcome stream across runs.
7. **Anti-gaming test (§9).** Feed a peer that (in the synthetic model) "advertises" high capacity but
   *measures* low; assert its rank tracks the measured (low) value, never the advertised one; assert
   a peer serving `VerificationFailed` ranges is driven below cold peers.
8. **Rebalance test (§5.5).** Mid-stream, drop an active peer and inject a fresh candidate; assert
   `rebalance` re-ranks using the up-to-the-moment models and picks a replacement for the still-needed
   ranges.

The **public API surface (§5)** and the **invariants (§4.4)** are the frozen conformance targets; a
change that alters a public signature or breaks an invariant is a breaking change and updates this
SPEC in the same unit of work.

---

## 9 · Security & trust

### 9.1 Peers are hints; only a completed mTLS transfer proves them

Every candidate the selector receives — from `dig-dht` providers, `dig-pex` exchange, or the gossip
pool — is a **hint**, exactly as in the dig-pex trust model. The selector MUST NOT treat a peer as
verified, reachable, content-holding, or high-quality on the basis of any received record. The only
proof is a **completed mTLS transfer with a measured, verified outcome**:

- A peer's identity is authoritative only as the transport-verified `peer_id = SHA-256(TLS SPKI
  DER)` that `dig-nat` confirmed — never a `peer_id` asserted in a payload (§2.4).
- A peer is proven to hold content only when a range from it yields a `Success` (and the bytes passed
  `dig-download`'s merkle verification, §6.3).
- Provenance and connection class (§2.2, §2.1) seed *priors* only; they never substitute for a
  measured outcome.

### 9.2 Scoring is measured-only

A peer's quality (§3) is refined **exclusively** from measured `TransferOutcome`s produced by the
executor from real transfers. There is deliberately **no** input path by which a peer can raise its
own score: the selector has no "advertised capacity" field that feeds the model, and it accepts no
quality assertion from the network. This is what makes the ranking **non-gameable by self-report**.

### 9.3 Observed capacity overrides advertised capacity

If any advertised/self-reported capacity is ever visible to the host (e.g. a hypothetical hint in a
peer record), the selector MUST treat it as **at most a tie-breaker among otherwise-equal cold
peers**, never as an input to `throughput`/`rtt` and never as a reason to prefer a peer over one with
better *measured* performance. A peer that claims fast and measures slow is ranked slow. Under no
configuration does advertised capacity override measured capacity.

### 9.4 Bad-source and hostile-peer handling

- A peer that serves ranges failing merkle verification (`VerificationFailed`, §6.3) MUST be driven
  toward the bottom of the ranking (below cold/unmeasured peers) so the selector routes around a bad
  or hostile source — matching the L7 rule that a bad range is refetched from another holder and the
  source penalized ([Peer network §9](https://docs.dig.net/docs/protocol/peer-network#multi-source)).
- A `Banned` peer (from `PoolEvent::PeerRemoved { reason: Banned }`) MUST be ineligible for selection
  until re-added by the pool.
- The selector cannot be poisoned by a flood of low-quality candidates: unmeasured peers get only
  bounded exploration (§4.4-E) and never displace proven peers; a peer that measures poorly falls in
  rank; the registry is bounded and evicts lowest-value entries (§2.5).

### 9.5 No new transport or authentication surface

The selector introduces no network endpoint, no message wire, and no credential. It cannot be
attacked directly over the network — it only consumes structured inputs from the sibling crates and
outputs rankings. All confidentiality/integrity/authentication properties are those of `dig-nat`
mTLS and `dig-download` verification; the selector adds none and weakens none.

---

## 10 · Backwards compatibility & versioning

- The public API (§5) is **version 1**. Evolution is **additive**: new optional fields on the
  logical types, new methods, new `FailureReason`/`OutcomeKind`/`Provenance` variants (consumers
  MUST ignore unknown variants where the wire crosses a boundary). Removing or repurposing a field or
  changing a method's semantics is a breaking change requiring an explicit version bump.
- The selector holds **no persisted on-disk format** in version 1 (learned state is in memory; the
  host owns any persistence, §6.4), so there is no stored-format compatibility surface to preserve
  yet. If a persisted snapshot format is added later, it MUST be versioned and additively evolved
  like every DIG format.
- Every behavior or API change updates this `SPEC.md` in the same unit of work.

---

## 11 · Public API summary (frozen surface)

Exported from the crate root; identity/candidate types re-used from `dig-nat` / `dig-dht`
(`#![forbid(unsafe_code)]`; license and MSRV mirror the sibling crates — `Apache-2.0 OR MIT`,
MSRV ≥ `1.75.0`):

- **`PeerSelector`** — `new(SelectorConfig)`, `select(&ContentRequest, &[Candidate]) -> Selection`,
  `rebalance(&ContentRequest, &[PeerId], &RangePlanDelta) -> Selection`,
  `record_outcome(&TransferOutcome)`, `on_pool_event(&PoolEvent)`,
  `on_connection_class(&PeerId, TraversalKind)`, `upsert_candidate(&Candidate)`,
  `remove_peer(&PeerId)`, plus read-only observability (§5.7).
- **Types:** `SelectorConfig` (§5.6), `ContentRequest` / `Candidate` / `Selection` / `SelectedPeer`
  (§5.1), `TransferOutcome` / `OutcomeKind` / `OutcomeResult` / `FailureReason` (§5.2),
  `RangePlanDelta` (§5.5), `PeerEntry` / `PeerQuality` / `Provenance` (§2–3, read-only snapshots),
  `PoolEvent` / `PoolRemovalReason` (§5.4 — mirrored byte-for-byte from `dig_gossip`).
- **Re-used (not redefined):** `dig_nat::{PeerId, TraversalKind}`, `dig_dht::{ContentId,
  ProviderRecord, CandidateAddr, AddressKind}`.
- **Mirrored byte-for-byte (not re-used, per the §5.4 binding note):** `PoolEvent` /
  `PoolRemovalReason` — field-identical to `dig_gossip`'s, sourced locally because `dig-gossip` pulls
  the whole chia stack and its current git tip does not compile as a dependency.

Dependency posture: depend on `dig-nat` and `dig-dht` for identity/candidate types (git-pinned bare
form until they are on crates.io); **mirror** the `dig-gossip` `PoolEvent` shape locally rather than
depending on `dig-gossip` (§5.4 binding note — keeps the tree minimal and the build green); do NOT
depend on `dig-download` for types the loop can express structurally (avoid a dependency cycle — the
outcome/event mapping lives in the host adapter, §6.2).

---

## 12 · Conformance summary

The frozen, testable statements of version 1. An implementation conforms iff all hold.

| ID | Statement |
|---|---|
| SEL-01 | The public API matches §5 exactly: `select`, `rebalance`, `record_outcome`, the four registry-feed hooks, and the §5.1/§5.2/§5.5 type shapes — re-using the `dig-nat`/`dig-dht` identity/candidate types (not parallel copies) and consuming the gossip churn event with the exact `dig_gossip::PoolEvent` shape (mirrored field-for-field per the §5.4 binding note, so a host maps `dig_gossip::PoolEvent` to it 1:1). |
| SEL-02 | The registry key is `peer_id = SHA-256(TLS SPKI DER)`; entries carry addresses, optional connection class, provenance, and a learned quality model; fed by gossip churn (`on_pool_event`) + DHT candidates passed to `select`; bounded with lowest-value eviction (§2). |
| SEL-03 | A peer's quality is refined ONLY from measured `TransferOutcome`s; throughput/RTT/reliability are recency-weighted estimators satisfying P-recency, P-monotone-convergence, P-responsive-degradation, P-volatility-tracking; observed capacity overrides advertised (§3, §9.2–9.3). |
| SEL-04 | Saturation point is learned per peer class and caps per-peer concurrency; the relayed penalty is learned from observed frequency + measured impact; decay is driven by observed volatility — none of these is a hardcoded constant or a user knob (§4.1–4.3, §1.5). |
| SEL-05 | Scoring satisfies invariants A–G (§4.4): convergence to fast/reliable peers, anti-thundering-herd load-spread, P99 orientation, degradation adaptation, bounded exploration, determinism under a fixed seed, bounded work. |
| SEL-06 | `record_outcome` updates the models in real time (per range, mid-transfer); `rebalance` re-queries the up-to-the-moment models for still-needed ranges, excluding saturated/failed active peers (§5.2–5.5). |
| SEL-07 | The `dig-download` loop contract holds: the selector drives source choice; `RangeCompleted`/`RangeFailed`/`Completed`/`Failed` map to `record_outcome` as they stream; a `VerificationFailed` range is a hard penalty driving the source below cold peers; a pause is not a failure; resume selects only the remaining ranges (§6). |
| SEL-08 | Integration inputs are read-only hints/choices: DHT `find_providers` provider records are candidates (hints); gossip `PoolEvent`/pool snapshot feed the registry; `dig-nat` `TraversalKind` seeds class/relay priors; the selector opens no transport and runs no discovery/DHT/transfer (§1.2, §7). |
| SEL-09 | Peers are proven only by a completed, verified mTLS transfer; identity is the transport-verified `peer_id`, never a payload field; there is no input path by which a peer raises its own score; a `Banned` peer is ineligible until re-added (§9). |
| SEL-10 | Backwards-compatible & additive: no user-facing behavior knobs; no persisted on-disk format in v1; every change updates this SPEC in the same unit of work (§1.5, §10). |
| SEL-11 | The learning + scoring are deterministic-testable over a synthetic-topology + throughput-trace harness (no real network) proving convergence, load-spread, degradation adaptation, P99 improvement, exploration, determinism, anti-gaming, and rebalance (§8). |

Cross-references: the DIG Protocol **Peer network** page (docs.dig.net → Protocol → Peer network)
defines the `peer_id`, the dual-transport tiers ([§0](https://docs.dig.net/docs/protocol/peer-network#dual-transport)), the connection-class ladder + relay-last
invariant ([§2](https://docs.dig.net/docs/protocol/peer-network#nat-traversal), [§10](https://docs.dig.net/docs/protocol/peer-network#invariant)), content discovery via the DHT ([§4c](https://docs.dig.net/docs/protocol/peer-network#dht)), PEX ([§4d](https://docs.dig.net/docs/protocol/peer-network#pex)), and the
byte-range multi-source download + per-range integrity + retry/penalize model ([§9](https://docs.dig.net/docs/protocol/peer-network#range)) this selector
optimizes. The superproject change-impact map records that a change to the shared identity /
candidate / event shapes must be mirrored across the affected modules in the same unit of work.

## 13 · References

- **`dig-dht`** — `find_providers` / `ProviderRecord` / `ContentId` / `CandidateAddr` (the candidate
  source, §7.1).
- **`dig-download`** — the executor: `Downloader::download`, the `DownloadEvent` stream
  (`RangeCompleted`/`RangeFailed`/`Completed`/`Failed`), per-range verification, and the
  `DownloadState` pause/resume model the feedback loop is bound to (§6).
- **`dig-gossip`** — the peer pool: `connected_pool_peers` / `subscribe_pool_events` (`PoolEvent`) /
  `pool_stats`, the topology feed (§7.2).
- **`dig-nat`** — the mTLS mux transport + `TraversalKind` connection class the transfers ride and the
  selector reads (§7.3).
- **`dig-pex`** — the peer-exchange trust model this selector mirrors: entries are hints, proven only
  by a verified connection (§9.1).
- **L7 · DIG Node peer network** — docs.dig.net → Protocol → Peer network (dual-transport, NAT ladder,
  DHT, PEX, multi-source download + integrity).
- RFC 2119 — requirement-level key words.
