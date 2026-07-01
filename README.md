# dig-peer-selector
DIG peer-selector — self-optimizing peer-selection middleware for the DIG Node: tracks network topology, learns per-peer latency/bandwidth from real download outcomes, and autonomously distributes multi-peer RPC/download requests to minimize P99 latency + avoid thundering-herd, with no user-facing knobs.
