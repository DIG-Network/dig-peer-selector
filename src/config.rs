//! [`SelectorConfig`] — **wiring only**, never behavior (SPEC.md §1.5, §5.6).
//!
//! The selector exposes NO settings that change its selection behavior. Every tradeoff (scoring
//! weights, decay constants, saturation limits, the relayed penalty) is a *learned internal state*,
//! not a knob. `SelectorConfig` therefore carries only pure wiring:
//!
//! - an injectable **clock** so tests drive time deterministically (no wall-clock reads inside the
//!   pure decision path);
//! - an optional **RNG seed** so exploration tie-breaks are reproducible (SPEC §4.4-F);
//! - a **registry capacity** — a pure resource bound (SPEC §2.5), not a behavior knob.
//!
//! Adding a scoring weight / decay constant / saturation limit / relayed-penalty field here is a
//! conformance failure (SPEC §5.6): such a quantity is learned, never configured.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// An injectable source of "now" in unix seconds.
///
/// The selector never reads the wall clock directly — every timestamp it needs (registry
/// `first_seen`, staleness for eviction) flows through a `ClockSource` so a test can advance time
/// deterministically and the §8 harness is reproducible. Production wires [`ClockSource::system`];
/// tests wire [`ClockSource::manual`].
#[derive(Clone)]
pub struct ClockSource {
    inner: ClockInner,
}

#[derive(Clone)]
enum ClockInner {
    /// Reads the real system clock (unix seconds).
    System,
    /// A test-controlled clock the harness advances explicitly.
    Manual(Arc<AtomicU64>),
}

impl ClockSource {
    /// A clock backed by the real system time (unix seconds).
    pub fn system() -> Self {
        ClockSource {
            inner: ClockInner::System,
        }
    }

    /// A deterministic, test-controlled clock starting at `start` unix seconds.
    ///
    /// Advance it with [`ClockSource::advance`] / [`ClockSource::set`]. This is what the conformance
    /// harness uses so time-dependent behavior (staleness, eviction age) is reproducible.
    pub fn manual(start: u64) -> Self {
        ClockSource {
            inner: ClockInner::Manual(Arc::new(AtomicU64::new(start))),
        }
    }

    /// The current time in unix seconds.
    pub fn now(&self) -> u64 {
        match &self.inner {
            ClockInner::System => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            ClockInner::Manual(t) => t.load(Ordering::Relaxed),
        }
    }

    /// Advance a manual clock by `secs`. No-op on a system clock.
    pub fn advance(&self, secs: u64) {
        if let ClockInner::Manual(t) = &self.inner {
            t.fetch_add(secs, Ordering::Relaxed);
        }
    }

    /// Set a manual clock to an absolute `secs`. No-op on a system clock.
    pub fn set(&self, secs: u64) {
        if let ClockInner::Manual(t) = &self.inner {
            t.store(secs, Ordering::Relaxed);
        }
    }
}

impl Default for ClockSource {
    fn default() -> Self {
        ClockSource::system()
    }
}

impl std::fmt::Debug for ClockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            ClockInner::System => f.write_str("ClockSource::System"),
            ClockInner::Manual(t) => {
                write!(f, "ClockSource::Manual({})", t.load(Ordering::Relaxed))
            }
        }
    }
}

/// The default registry capacity — a pure resource bound (SPEC §2.5), NOT a behavior knob.
///
/// Large enough that a healthy node never sheds a useful peer under normal operation; when exceeded,
/// the lowest-value entries are evicted (never a connected peer or one with a range in flight).
pub const DEFAULT_REGISTRY_CAPACITY: usize = 4096;

/// Wiring-only configuration for a [`crate::PeerSelector`] (SPEC §5.6).
///
/// Carries an injectable clock, an optional RNG seed for deterministic exploration tie-breaks, and a
/// registry capacity bound. It MUST NOT carry scoring weights, decay constants, saturation limits, or
/// a relayed penalty — those are learned (SPEC §1.5). Adding such a field is a conformance failure.
#[derive(Clone, Debug)]
pub struct SelectorConfig {
    /// The injectable clock (tests drive time deterministically). Default: the system clock.
    pub clock: ClockSource,
    /// Seed for the exploration tie-break PRNG (SPEC §4.4-F). `None` derives a fixed default seed so
    /// behavior is still deterministic across runs of the same registry + outcome stream.
    pub rng_seed: Option<u64>,
    /// The registry capacity — a resource bound (SPEC §2.5), not a behavior knob.
    pub registry_capacity: usize,
}

impl Default for SelectorConfig {
    fn default() -> Self {
        SelectorConfig {
            clock: ClockSource::system(),
            rng_seed: None,
            registry_capacity: DEFAULT_REGISTRY_CAPACITY,
        }
    }
}

impl SelectorConfig {
    /// A config with a deterministic manual clock (starting at `start` unix seconds) and a fixed RNG
    /// seed — the shape the §8 conformance harness uses for reproducibility.
    pub fn deterministic(start: u64, seed: u64) -> Self {
        SelectorConfig {
            clock: ClockSource::manual(start),
            rng_seed: Some(seed),
            registry_capacity: DEFAULT_REGISTRY_CAPACITY,
        }
    }

    /// The effective RNG seed (the configured seed, or a fixed default so runs are reproducible even
    /// without an explicit seed — SPEC §4.4-F).
    pub(crate) fn effective_seed(&self) -> u64 {
        self.rng_seed.unwrap_or(0x5EED_D16C_0DE0_u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_and_sets() {
        let c = ClockSource::manual(100);
        assert_eq!(c.now(), 100);
        c.advance(50);
        assert_eq!(c.now(), 150);
        c.set(10);
        assert_eq!(c.now(), 10);
    }

    #[test]
    fn system_clock_is_nonzero_and_ignores_manual_ops() {
        let c = ClockSource::system();
        assert!(c.now() > 1_600_000_000); // after 2020
        c.advance(1000); // no-op on system clock
        c.set(0); // no-op
        assert!(c.now() > 1_600_000_000);
    }

    #[test]
    fn default_config_uses_system_clock_and_default_capacity() {
        let cfg = SelectorConfig::default();
        assert_eq!(cfg.registry_capacity, DEFAULT_REGISTRY_CAPACITY);
        assert!(cfg.rng_seed.is_none());
        // effective seed is deterministic even without an explicit seed.
        assert_eq!(
            cfg.effective_seed(),
            super::SelectorConfig::default().effective_seed()
        );
        assert_ne!(
            cfg.effective_seed(),
            0,
            "the fixed default seed is deterministic + non-zero"
        );
    }

    #[test]
    fn deterministic_config_is_reproducible() {
        let a = SelectorConfig::deterministic(1000, 42);
        let b = SelectorConfig::deterministic(1000, 42);
        assert_eq!(a.clock.now(), b.clock.now());
        assert_eq!(a.effective_seed(), b.effective_seed());
        assert_eq!(a.effective_seed(), 42);
    }

    #[test]
    fn clock_debug_renders() {
        assert!(format!("{:?}", ClockSource::system()).contains("System"));
        assert!(format!("{:?}", ClockSource::manual(7)).contains('7'));
    }
}
