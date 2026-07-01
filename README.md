# dig-peer-selector

**Self-optimizing peer-selection middleware for the DIG Node.** It tracks live network topology,
learns each peer's real latency/bandwidth from actual download outcomes, and autonomously chooses the
best peer subset for every multi-peer RPC/download request — minimizing P99 latency and avoiding
thundering-herd on high-capacity peers, **with no user-facing configuration knobs**.

> **Status: SPEC/PROMPT ONLY — not yet implemented.** This README is the build brief. Pick it up later:
> author `SPEC.md` first (normative, per the ecosystem rule), then implement to it TDD, then integrate
> into the DIG Node. Ships as a `modules/crates/` submodule of the `dig_ecosystem` superproject.

---

## What to build

A Rust crate, `dig-peer-selector`, that sits between the DIG Node's download path and the peer network.
Its job: given a content request, return the **best peer subset** to fetch from; then absorb the actual
throughput outcome of that fetch and use it to get smarter — a fully autonomous feedback loop that needs
no manual tuning.

### Core requirements

1. **Dynamic peer registry.** Maintain a live registry of candidate peers that updates as peers join or
   leave. It does NOT discover peers itself — it is fed by the existing discovery layers (see Integration).
   Each registry entry carries the peer identity (`peer_id = SHA-256(TLS SPKI DER)`), its reachable
   candidate addresses + connection class (direct / UPnP-mapped / hole-punched / relayed), and the learned
   quality model below.

2. **Continuous per-peer learning.** Learn each peer's latency and bandwidth capability from REAL download
   performance — every completed (or failed/interrupted) byte-range transfer feeds back its measured
   throughput, RTT, and success/failure. Do not rely on advertised/self-reported capacity; learn observed
   capacity. Maintain a per-peer capacity model (e.g. an EWMA/decaying estimate of achievable throughput +
   latency + a reliability score) that is refined on every outcome.

3. **Autonomous scoring function.** Score peers to balance **fast-peer utilization** against **load
   spreading**, learning — not hardcoding — the tradeoffs:
   - learn each peer's optimal **saturation point** (concurrent in-flight ranges beyond which its
     throughput degrades) per peer *type/class*, and stop piling requests past it;
   - automatically adjust the **penalty for relayed connections** based on their observed frequency and
     real performance impact (a relayed peer that happens to be fast should not be over-penalized; a
     consistently slow one should be);
   - **decay** peer quality scores according to the temporal patterns it observes (recency-weighted; a
     peer that was fast an hour ago but is now degraded should fall off). No fixed decay constant baked in
     as policy — the decay should track observed volatility.

4. **Retroactive capacity refinement.** Learn from EVERY download request's actual throughput outcome:
   retroactively update the peer capacity models AND refine future selection decisions. The optimization
   targets are explicit: **minimize P99 latency** across requests while **avoiding thundering-herd**
   patterns on high-capacity peers (don't send everyone to the one fast peer and collapse it).

5. **The request/feedback loop.** The public surface is small and closed-loop:
   - the download path **queries** the selector for the best peer subset for a given content request
     (content id + expected size / range plan + how many parallel sources are wanted);
   - the download crate **executes** the multi-peer transfer (with pause/resume — see `dig-download`);
   - the selector **internalizes feedback in real time** — per-range and per-request outcomes stream back
     as they happen, updating the models mid-transfer so an in-flight download can be re-balanced.
   The loop is fully autonomous: it improves the selection strategy without user intervention or manual
   parameter tuning. **No configuration knobs are exposed to the user** — any internal hyperparameters are
   self-tuned from observed data, not surfaced as settings.

### Non-goals / boundaries

- It does NOT do transport, NAT traversal, discovery, the DHT lookup, or the actual byte transfer — it
  only *selects* + *learns*. The other crates own those (see below).
- It exposes no user-facing tuning surface. (Internal observability/metrics for debugging are fine, but
  not knobs that change behavior.)
- Keep it deterministic-testable: the learning + scoring must be unit-testable with synthetic
  outcome streams (no real network) — e.g. feed it a simulated topology + throughput traces and assert the
  selection converges to the fast/reliable peers, spreads load off a saturating peer, and adapts when a
  peer degrades.

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
- **`dig-download`** — the EXECUTOR + FEEDBACK PRODUCER. This is the tight loop: `dig-download`'s
  multi-source range scheduler asks the selector for the best peer subset per download (and per re-balance
  when a source drops / a range needs relocating), executes the byte-range fan-out with pause/resume +
  per-chunk merkle verification, and streams every range's measured outcome (throughput, latency,
  success/fail, which peer, which range size) back into the selector. dig-download already re-queues a bad
  range to another provider — the selector should DRIVE that choice + LEARN from the failure.
- **`dig-node`** (in digstore) — the HOST that owns the instances and wires them together: it constructs
  the selector, feeds it the gossip pool + dig-nat connection classes, passes dig-dht providers in on each
  content-want, and hands the selector↔dig-download loop the content requests. The selector is a dependency
  of the node's content-fetch path (the same path #164/#165 build).

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

## Deliverables when picked up

1. **`SPEC.md`** — normative: the registry model, the per-peer capacity/quality model, the scoring
   function's learned quantities (saturation point, relayed penalty, decay), the optimization objective
   (min P99 + anti-thundering-herd), the public API (`select` / `record_outcome` / registry-feed hooks /
   churn subscription), and the feedback-loop contract with `dig-download`. Spec-first.
2. **Implementation** to the spec, TDD, over a synthetic-topology test harness (no real network); the
   learning must demonstrably converge + adapt in tests.
3. **CI** mirroring the sibling crates: `ci.yml` (fmt + clippy `-D warnings` + test) + coverage gate
   (`cargo llvm-cov --fail-under-lines 80`) + tag-driven `publish.yml` (crates.io, `CARGO_REGISTRY_TOKEN`,
   pinned action SHAs). Full crates.io `Cargo.toml` metadata; DIG-crate deps git-pinned like the others.
4. **Integration** into the dig-node content-fetch path (digstore `crates/dig-node`) + the selector↔
   dig-download loop, and doc the selection layer in `docs.dig.net` (peer-network / download flow) +
   `SYSTEM.md`.

## Ecosystem conventions (must follow)

- Peer identity is `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)` everywhere (same as dig-nat/dig-gossip/
  dig-dht/dig-pex).
- All node-to-node traffic is mTLS via dig-nat; the selector never opens its own transport.
- Backwards-compatible, additive; every change updates `SPEC.md` in the same unit of work.
- No commit footers / no co-authoring lines.
