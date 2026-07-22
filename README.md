# dig-peer-selector

**Self-optimizing peer-selection middleware for the DIG Node.** It tracks live network topology,
learns each peer's real latency/bandwidth from actual download outcomes, and autonomously chooses the
best peer subset for every multi-peer RPC/download request — minimizing P99 latency and avoiding
thundering-herd on high-capacity peers, **with no user-facing configuration knobs**.

> **Status: implemented to `SPEC.md` (API version 1).** The crate is the pure decision + learning layer;
> `SPEC.md` is the normative contract. The dig-node integration (wiring the selector between `dig-dht` and
> `dig-download` in digstore) is the remaining follow-up. Ships as a `modules/crates/` submodule of the
> `dig_ecosystem` superproject.

---

## What it is

A Rust crate, `dig-peer-selector`, that sits between the DIG Node's download path and the peer network.
Given a content request it returns the **best peer subset** to fetch from; then it absorbs the actual
throughput outcome of that fetch and gets smarter — a fully autonomous feedback loop that needs no manual
tuning. It opens no socket, runs no discovery, and exposes **no user-facing configuration knobs**: every
tradeoff (saturation point, relayed penalty, decay) is self-tuned from observed data.

### Public API (frozen surface, `SPEC.md` §5/§11)

```rust
use dig_peer_selector::{PeerSelector, SelectorConfig, ContentRequest, Candidate,
                        Selection, TransferOutcome, RangePlanDelta};

let selector = PeerSelector::new(SelectorConfig::default());       // no behavior knobs
let selection: Selection = selector.select(&request, &candidates); // ranked subset + per-peer max_concurrency
selector.record_outcome(&outcome);                                 // measured result, folded in real time
let replacement = selector.rebalance(&request, &active, &need);    // mid-transfer re-query
// registry feeds: on_pool_event, on_connection_class, upsert_candidate, remove_peer
// read-only observability: peer_snapshot, snapshot, registry_size
```

### What it does (all learned, measured-only, non-gameable)

1. **Dynamic peer registry** — fed by the discovery layers (gossip churn + DHT candidates), keyed by
   `peer_id = SHA-256(TLS SPKI DER)`, bounded with lowest-value eviction; a reconnecting peer keeps its
   learned history.
2. **Continuous per-peer learning** — throughput / RTT / reliability learned from the REAL measured
   outcome of every transfer; observed capacity always overrides advertised (there is no input path by
   which a peer raises its own score).
3. **Autonomous scoring** — a learned per-class **saturation point** (anti-thundering-herd), an adaptive
   **relayed penalty**, and a decay derived from each peer's observed **volatility** (no baked constant).
4. **Objective** — minimize P99 request latency while avoiding thundering-herd collapse on a fast peer.
5. **Closed loop** — `select → execute (dig-download) → record_outcome → rebalance`, updating the models
   mid-transfer so an in-flight download re-balances.

### Boundaries

- It does NOT do transport, NAT traversal, discovery, the DHT lookup, or the byte transfer — it only
  *selects* + *learns*. The sibling crates own those (see Integration).
- No user-facing tuning surface (read-only observability is fine; behavior knobs are not).
- Deterministic-testable: the learning + scoring are proven over a synthetic-topology + throughput-trace
  harness (no real network) in `tests/conformance.rs` — convergence, load-spread, degradation adaptation,
  P99 orientation, bounded exploration, seed-determinism, anti-gaming, and rebalance.

---

## Integration with the existing DIG Node P2P stack

The selector is the "brain"; these crates are the "senses + hands". Wire it as middleware between
`dig-download` and the peer layer.

- **`dig-dht`** (`find_providers`) — the CANDIDATE SOURCE. When the node wants content, dig-dht returns
  the set of provider peers (peer_id + addresses) holding it. Those candidates are the input population the
  selector scores/ranks. The selector filters + orders them; it does not query the DHT itself (the node
  does that and hands the providers in).
- **`dig-pex` / `dig-gossip`** — the LIVE TOPOLOGY FEED. The gossip peer pool + PEX peer-exchange keep a
  continuously-updated view of which peers exist + are connected (join/leave churn, connection class,
  `via` provenance). The selector's dynamic registry is fed from this pool (subscribe to pool churn events
  — dig-gossip already exposes `subscribe_pool_events` / `connected_pool_peers` / `pool_stats`). PEX-learned
  peers arrive as hints; the selector treats a peer's quality as unknown until it has real outcome data.
- **`dig-nat`** — the CONNECTION-CLASS + TRANSPORT signal. dig-nat established each peer connection via its
  ladder (direct → UPnP → NAT-PMP → PCP → hole-punch → relayed-TURN) and knows which method won + exposes
  it. The selector reads that connection class per peer (esp. "relayed" vs "direct") to seed the
  relayed-penalty learning, and the actual transfers ride dig-nat's mTLS mux streams.
- **`dig-peer`** — the CONNECTION BUILDER. The selector returns ranked `PeerId`s in each `Selection`; the
  node uses `dig-peer` to establish connections: construct a `PeerTarget` from the `peer_id` + candidate
  addresses, call `DigPeer::connect` to establish mTLS, and use the resulting `Connected` streams for the
  data transfer. The selector is agnostic to transport mechanics — it only ranks peers and learns from
  outcomes. Connection establishment is entirely the node's responsibility via `dig-peer`.
- **`dig-download`** — the EXECUTOR + FEEDBACK PRODUCER. This is the tight loop: `dig-download`'s
  multi-source range scheduler asks the selector for the best peer subset per download (and per re-balance
  when a source drops / a range needs relocating), executes the byte-range fan-out with pause/resume +
  per-chunk merkle verification, and streams every range's measured outcome (throughput, latency,
  success/fail, which peer, which range size) back into the selector. dig-download already re-queues a bad
  range to another provider — the selector should DRIVE that choice + LEARN from the failure.
- **`dig-node`** (in digstore) — the HOST that owns the instances and wires them together: it constructs
  the selector, feeds it the gossip pool + dig-nat connection classes, passes dig-dht providers in on each
  content-want, and hands the selector↔dig-download loop the content requests. It uses dig-peer to
  establish connections to selected peers. The selector is a dependency of the node's content-fetch path
  (the same path #164/#165 build).

### The end-to-end flow (what to implement to)

```
content want (store/capsule/root/.dig)
  → dig-node: dig-dht.find_providers(content_id)          → candidate peers
  → dig-peer-selector.select(content_req, candidates)     → ranked best peer subset
  → dig-download.download(req, subset, sink)               → multi-peer byte-range fan-out (pause/resume,
                                                             per-chunk merkle verify) over dig-nat mTLS mux
  → per-range/per-request outcomes stream back
  → dig-peer-selector.record_outcome(...)                 → update capacity models + scores in real time
  → next select() (and mid-transfer re-balance) is smarter — autonomous, no user tuning
```

---

## Status of the deliverables

1. **`SPEC.md`** — DONE (normative, API version 1): the registry model, the per-peer capacity/quality
   model, the learned scoring quantities (saturation point, relayed penalty, volatility-driven decay), the
   min-P99 + anti-thundering-herd objective, the public API, and the feedback-loop contract with
   `dig-download`.
2. **Implementation** — DONE, TDD, over the synthetic-topology harness (`tests/conformance.rs`, no real
   network); the learning converges + adapts in the conformance tests (SEL-01..SEL-11).
3. **CI** — DONE, mirroring the sibling crates: `ci.yml` (fmt + clippy `-D warnings` + test + docs) +
   coverage gate (`cargo llvm-cov --fail-under-lines 80`) + tag-driven `publish.yml` (crates.io,
   `CARGO_REGISTRY_TOKEN`). Full crates.io `Cargo.toml` metadata; DIG-crate deps git-pinned like the others.
4. **Integration** — FOLLOW-UP: wire the selector into the dig-node content-fetch path (digstore
   `crates/dig-node`) as the source-selection seam of the selector↔dig-download loop, and document the
   selection layer in `docs.dig.net` (peer-network / download flow) + `SYSTEM.md`. See the implementers'
   note in `src/lib.rs` for exactly how dig-node embeds the selector.

## Ecosystem conventions (followed)

- Peer identity is `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)` everywhere (re-used from dig-nat;
  same as dig-gossip / dig-dht / dig-pex).
- All node-to-node traffic is mTLS via dig-nat; the selector never opens its own transport.
- Backwards-compatible, additive; every change updates `SPEC.md` in the same unit of work.
- No commit footers / no co-authoring lines.
