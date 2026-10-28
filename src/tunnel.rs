//! DNS-tunneling heuristic detection.
//!
//! REQ RUNUT-DNS-TUNNEL-DETECT-001. Alert-only, logs and counts, never
//! blocks or alters resolution -- same posture as `dga.rs`'s DGA detector,
//! which this module deliberately does NOT duplicate or replace (see
//! `dga.rs`'s own module doc comment, which flags this exact feature as a
//! separate, not-yet-built follow-on when it shipped).
//!
//! # Why distinct-subdomain-count, not per-query entropy
//!
//! DNS tunneling encodes exfiltrated/C2 data into DNS queries, typically as
//! many unique, high-entropy subdomains under one attacker-controlled parent
//! domain (e.g. `aGVsbG8gd29ybGQ.data1.evil.com`, a new unique subdomain
//! roughly every query). A single-query stateless heuristic -- entropy or
//! length of one label, `dga.rs`'s own approach for DGA -- is deliberately
//! NOT used as this detector's primary trigger. Legitimate traffic (CDNs,
//! cloud storage, container orchestration, chat/telemetry SDKs) routinely
//! uses long, high-entropy-*looking* subdomains too (content hashes, pod
//! IDs, session tokens), so a per-query entropy gate alone would false-
//! positive constantly on entirely normal traffic.
//!
//! The reliable signal is different: legitimate traffic re-queries a small,
//! stable *set* of subdomains under any given domain (a CDN edge might use a
//! handful of shard names; a chat client reconnects to the same few
//! endpoint hostnames), while DNS tunneling generates a new, previously-
//! unseen distinct subdomain on almost every single query, because each
//! query IS a packet of exfiltrated data. So this module tracks, per
//! registrable domain, how many *distinct* subdomain chains have been seen
//! within a bounded retention window, and gates on THAT count crossing a
//! threshold (`TunnelTracker`/`evaluate`). Per-query signals (query type,
//! chain length, entropy of the subdomain chain) are computed too
//! (`static_reasons`), but only as secondary, corroborating `reasons`
//! strings attached to an already-triggered alert -- never as the primary
//! trigger gate themselves.
//!
//! # Panic-safety (inherited from dga.rs, applies equally here)
//!
//! This code is reachable from `handle_query_internal` on every query when
//! `tunnel.enabled` is true. `labels` is 100% attacker-controlled wire-
//! format DNS label bytes, and this crate builds with `panic = "abort"` in
//! release -- a panic here kills DNS resolution for the entire network this
//! resolver serves, not just one request. Every function in this module
//! that touches label content is written to return `None`/skip cleanly on
//! empty input, non-UTF-8 content, or any other adversarial shape, never to
//! panic or index out of bounds. See `no_panic_on_adversarial_tunnel_input`
//! below for the fuzz sweep this is checked against.

use crate::dga;
use crate::tameng;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::num::NonZeroUsize;

/// Standard DNS RR type IDs (NULL is RFC 1035 §3.3.10, TXT is RFC 1035
/// §3.3.14; both are long-stable, never-renumbered values from the core DNS
/// spec) that tunneling implementations commonly favor because they can carry
/// arbitrary/larger payloads in the *response* direction, not just the
/// query name. Corroborating signal only -- plenty of legitimate TXT/NULL
/// traffic exists (SPF/DKIM/domain verification records), so this alone
/// never gates anything.
const QTYPE_TXT: u16 = 16;
const QTYPE_NULL: u16 = 10;

/// Maximum total DNS wire-format name length in bytes, per RFC 1035 §3.1.
const MAX_WIRE_NAME_LEN: usize = 253;

/// Maximum single DNS wire-format label length in bytes, per RFC 1035
/// §3.1.
const MAX_WIRE_LABEL_LEN: usize = 63;

/// Corroborating-signal threshold for `(sum of subdomain label lengths) /
/// MAX_WIRE_NAME_LEN` -- crossed when the subdomain portion alone consumes
/// more than half of the entire 253-byte wire name budget. Not
/// corpus-validated (same honest caveat as dga.rs's own weights): a
/// reasonable starting point given exfiltration payloads are typically
/// packed as densely as the wire format allows, while legitimate subdomain
/// chains rarely approach this.
const LONG_CHAIN_LENGTH_RATIO_THRESHOLD: f64 = 0.5;

/// Corroborating-signal threshold for `(longest single subdomain label
/// length) / MAX_WIRE_LABEL_LEN` -- crossed when one label alone is packed
/// to more than 80% of the maximum a single DNS label can hold. Tunneling
/// implementations commonly pack each label as close to the 63-byte ceiling
/// as possible to minimize the number of queries needed per byte of
/// exfiltrated data.
const LONG_LABEL_RATIO_THRESHOLD: f64 = 0.8;

/// Bounded-memory tracker of distinct subdomain-chains seen per registrable
/// domain. Outer LRU keyed on the registrable domain's raw label bytes,
/// mapping to an inner fixed-capacity LRU of distinct subdomain-chains seen
/// for that domain -- both LRUs, not hash sets, for the same reason
/// `dga_alert_seen`/`tameng_send_seen` in server/mod.rs are LRUs: a fixed
/// memory bound under attacker-controlled cardinality, at the cost of
/// evicted entries "forgetting" and being re-counted from scratch (accepted
/// imprecision, documented on `record` below).
///
/// # Inner-key design: `u64` hash, not raw `Vec<Vec<u8>>` (HIGH-1/HIGH-2)
///
/// The INNER LRU is keyed on a `u64` hash of the subdomain-chain, not the
/// raw `Vec<Vec<u8>>` label bytes. An earlier version kept the raw label
/// vectors as the inner key too; an independent review measured that at the
/// shipped default capacities (2000 outer x 256 inner) this cost ~3GB
/// worst-case resident memory (a legal max-label-count 124-label name costs
/// ~6KB per raw key) and ~500 heap allocations per query -- a 28x per-query
/// CPU amplification -- all performed behind a single global outer mutex,
/// serializing that cost across every worker thread. On the resolver's
/// target 2-4GB VPS class at a 100K QPS target, this was a real OOM/
/// throughput risk once `tunnel.enabled: true`. The inner LRU never reads a
/// chain's bytes back (it only tests equality/counts distinctness), so a
/// fixed 8-byte hash serves the same purpose at a fraction of the cost.
///
/// The hash is computed by calling `.hash()` directly on the `&[Vec<u8>]`
/// subdomain slice -- i.e. reusing `Vec<Vec<u8>>`'s (and `[Vec<u8>]`'s) own
/// derived `Hash` impl, which already hashes length-then-bytes per label in
/// sequence and is therefore already label-boundary-safe on its own
/// (`[b"ab", b"c"]` and `[b"a", b"bc"]` hash differently -- see
/// `record_label_boundary_split_of_same_total_bytes_are_distinct_chains`
/// below). This deliberately does NOT reimplement hashing via manual
/// concatenation of the label bytes -- see `dga.rs`'s and `tameng.rs`'s own
/// doc comments on why a naive join/concatenation of wire-format labels is
/// unsafe in general (the exact desync bug class this codebase has already
/// been burned by and carries dedicated regression tests against).
///
/// **Accepted tradeoff: a 64-bit hash has a small, non-zero collision
/// probability.** Two genuinely distinct subdomain chains could -- with
/// vanishingly small but non-zero probability -- hash to the same `u64` and
/// be undercounted as one entry. At the default `tracker_inner_capacity` of
/// 256 entries per domain this is a birthday-bound risk on the order of
/// 256^2 / 2^65 (utterly negligible), and an attacker would additionally
/// need to find a collision under a secret, randomly-seeded key they cannot
/// observe (see `hash_builder` below) to have any hope of exploiting it
/// deliberately. Documented honestly here rather than asserting a false
/// zero-collision guarantee, matching this codebase's established pattern
/// of documenting known limitations plainly (see `dga_alert_seen`'s own
/// fixed-capacity-not-time-windowed field doc comment in server/mod.rs, and
/// `record`'s own "Accepted imprecision" section below).
///
/// The OUTER key is deliberately left as the raw `Vec<Vec<u8>>` registrable-
/// domain label bytes (unchanged from the original design): it is far
/// lower cardinality (bounded by `tracker_outer_capacity`, default 2000,
/// vs. the inner LRU's up-to-512,000-entry worst case across all domains),
/// so its clone/memory cost is comparatively negligible and hashing it
/// would provide no measurable benefit here -- see
/// `dga::split_subdomain_and_registrable`'s doc comment for why
/// `Vec<Vec<u8>>` (never a joined/dot-delimited string) is still the right
/// representation for a value like this.
pub struct TunnelTracker {
    outer: parking_lot::Mutex<lru::LruCache<Vec<Vec<u8>>, lru::LruCache<u64, ()>>>,
    inner_capacity: NonZeroUsize,
    /// Seeded ONCE in `TunnelTracker::new` and reused via `build_hasher()`
    /// for every hash computation over this tracker's ENTIRE lifetime. This
    /// is essential for correctness, not just a style choice or DoS-
    /// resistance nicety: if a fresh `RandomState` were constructed per call
    /// (e.g. `RandomState::new().build_hasher()` inline inside `record`),
    /// the same subdomain chain would hash to a DIFFERENT `u64` on every
    /// call, so it would never be recognized as a repeat and distinct-
    /// counting would be completely broken. Do NOT "simplify" this back to
    /// a fresh `RandomState::new()` per call.
    ///
    /// `RandomState`, specifically NOT
    /// `std::collections::hash_map::DefaultHasher::new()`:
    /// `DefaultHasher::new()` uses a fixed, publicly-known seed (0, 0), so
    /// an attacker who knows this tracker hashes with the stdlib default
    /// hasher could potentially engineer chosen subdomain chains to
    /// collide, keeping their own `distinct_count` artificially low and
    /// evading detection -- the exact opposite of what this detector exists
    /// to catch. `RandomState` is randomly seeded once at construction --
    /// the same DoS-resistance mechanism `std::collections::HashMap`'s own
    /// default hasher relies on.
    hash_builder: RandomState,
}

impl TunnelTracker {
    /// # Panics
    ///
    /// Panics if `outer_capacity` or `inner_capacity` is 0. Both are
    /// validated to be `> 0` at config-load time (`Config::load`, see
    /// config.rs's `tunnel.tracker_outer_capacity`/`tracker_inner_capacity`
    /// checks) specifically so this constructor -- called once at startup
    /// from `DnsServer::new`, never per-query -- can rely on an
    /// already-validated value rather than needing to fail gracefully at
    /// runtime. Mirrors `dga_alert_seen`'s/`tameng_send_seen`'s own
    /// `NonZeroUsize::new(...).unwrap()` construction in server/mod.rs.
    pub fn new(outer_capacity: usize, inner_capacity: usize) -> Self {
        let outer_cap = NonZeroUsize::new(outer_capacity)
            .expect("tunnel.tracker_outer_capacity must be > 0 (validated at config load)");
        let inner_cap = NonZeroUsize::new(inner_capacity)
            .expect("tunnel.tracker_inner_capacity must be > 0 (validated at config load)");
        Self {
            outer: parking_lot::Mutex::new(lru::LruCache::new(outer_cap)),
            inner_capacity: inner_cap,
            // Constructed exactly ONCE here, never per-call -- see the
            // field's own doc comment above for why re-seeding per call
            // would silently break distinct-counting entirely.
            hash_builder: RandomState::new(),
        }
    }

    /// Records this subdomain-chain as seen under this registrable domain,
    /// returns the current distinct-subdomain-chain count for that domain
    /// (post-insert).
    ///
    /// # Accepted imprecision
    ///
    /// The returned count can never exceed `inner_capacity`, since the
    /// inner LRU itself is capacity-bounded: a domain that legitimately
    /// churns through more than `inner_capacity` distinct real subdomains
    /// plateaus at `inner_capacity` rather than growing further once it
    /// evicts its own older entries, and could keep false-triggering past
    /// that point for as long as it keeps querying. This is the same class
    /// of tradeoff `dga_alert_seen`'s fixed-capacity-not-time-windowed
    /// design already accepts (see its field doc comment in
    /// server/mod.rs): a hard memory bound is preferred over unbounded
    /// per-domain growth, and an evicted-then-reseen chain simply gets
    /// re-counted rather than remembered forever.
    ///
    /// Additionally, since HIGH-1/HIGH-2 (see `TunnelTracker`'s struct doc
    /// comment), the inner LRU is keyed on a `u64` hash of
    /// `subdomain_labels` rather than the raw label bytes -- two distinct
    /// chains could, with negligible but non-zero probability, hash to the
    /// same key and be undercounted as one. Same "document, don't hide"
    /// tradeoff style as the plateau behavior above.
    fn record(&self, registrable_domain_labels: &[Vec<u8>], subdomain_labels: &[Vec<u8>]) -> usize {
        // Hash the subdomain chain via its own derived `Hash` impl (through
        // this tracker's single, fixed-for-its-lifetime `hash_builder`),
        // NOT a manual concatenation of the label bytes -- `[Vec<u8>]`'s
        // impl already hashes length-then-bytes per label in sequence, so
        // this is boundary-safe for free (see
        // `record_label_boundary_split_of_same_total_bytes_are_distinct_chains`
        // below). Computed before taking the lock: hashing doesn't need it.
        let mut hasher = self.hash_builder.build_hasher();
        subdomain_labels.hash(&mut hasher);
        let chain_hash = hasher.finish();

        let mut outer = self.outer.lock();
        let key = registrable_domain_labels.to_vec();
        if outer.get_mut(&key).is_none() {
            outer.put(key.clone(), lru::LruCache::new(self.inner_capacity));
        }
        let inner = outer
            .get_mut(&key)
            .expect("just inserted above if it wasn't already present");
        inner.put(chain_hash, ());
        inner.len()
    }
}

/// A DNS-tunneling suspicion score in [0.0, 1.0] plus supporting detail, for
/// logging/TAMENG forwarding.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelScore {
    pub score: f64,
    pub distinct_count: usize,
    /// Safely escaped, UTF-8-validated display form of the registrable
    /// domain (via `tameng::build_alert_domain`) -- suitable for logging
    /// and as the outbound TAMENG `domain` field. NOT a raw/lossy decode;
    /// see `evaluate`'s doc comment for why the whole call fails (`None`)
    /// rather than falling back to a placeholder when this can't be built.
    pub registrable_domain: String,
    pub reasons: Vec<&'static str>,
}

/// Concatenates all subdomain labels' bytes (NOT dot-joined -- entropy is
/// computed over the character distribution only, order/boundaries don't
/// matter for that math, and a dot-join here would just add characters that
/// skew the entropy calculation) into one `String`, or `None` if any label
/// is not valid UTF-8. Mirrors `dga.rs::score`'s "non-UTF-8 means not
/// scored" contract, applied to every subdomain label rather than one
/// registrable label.
fn concatenated_subdomain_utf8(subdomain_labels: &[Vec<u8>]) -> Option<String> {
    let mut buf = String::new();
    for label in subdomain_labels {
        buf.push_str(std::str::from_utf8(label).ok()?);
    }
    Some(buf)
}

/// Per-query corroborating signals, computed from the subdomain chain and
/// query type. Secondary/context-only, NOT the primary trigger gate -- see
/// this module's doc comment. Each signal independently no-ops (contributes
/// no reason) rather than panicking on empty/non-UTF-8/adversarial input;
/// there is no failure mode here that stops the others from being checked.
fn static_reasons(subdomain_labels: &[Vec<u8>], qtype: u16) -> Vec<&'static str> {
    let mut reasons = Vec::new();

    if qtype == QTYPE_TXT || qtype == QTYPE_NULL {
        reasons.push("tunnel_prone_qtype");
    }

    let total_len: usize = subdomain_labels.iter().map(Vec::len).sum();
    if (total_len as f64 / MAX_WIRE_NAME_LEN as f64) > LONG_CHAIN_LENGTH_RATIO_THRESHOLD {
        reasons.push("long_subdomain_chain_length");
    }

    if let Some(longest) = subdomain_labels.iter().map(Vec::len).max() {
        if (longest as f64 / MAX_WIRE_LABEL_LEN as f64) > LONG_LABEL_RATIO_THRESHOLD {
            reasons.push("long_subdomain_label");
        }
    }

    // Entropy over the FULL concatenated subdomain chain, not just one
    // label (unlike dga.rs's single-registrable-label approach) -- tunneling
    // payloads are typically spread across multiple labels once the data
    // needs to exceed the 63-byte single-label ceiling, so scoring only the
    // last/first label would miss most of the actual encoded content.
    if let Some(chain) = concatenated_subdomain_utf8(subdomain_labels) {
        let len = chain.chars().count();
        if dga::entropy_ratio(&chain, len) > dga::high_entropy_ratio_threshold() {
            reasons.push("high_entropy_subdomain_chain");
        }
    }

    reasons
}

/// Divisor for the bounded score formula in `evaluate`: `score` reaches
/// `1.0` at `SCORE_HEADROOM_MULTIPLIER`x the configured threshold, not
/// exactly at the threshold itself. Chosen (not corpus-validated, same
/// honest caveat as elsewhere in this module) so a score of `1.0` is
/// reserved for domains substantially past the trigger point, giving a
/// meaningful gradient between "just crossed the threshold" (score just
/// above 0) and "clearly, heavily tunneling" (score at or near 1.0) for any
/// future log/alert-severity tiering, instead of every triggering domain
/// reading as maximally severe immediately upon crossing.
const SCORE_HEADROOM_MULTIPLIER: f64 = 2.0;

/// Entry point: evaluates one query's labels against `tracker`'s
/// accumulated per-domain state and returns a `TunnelScore` when the
/// registrable domain's distinct-subdomain-chain count is at or above
/// `threshold`.
///
/// Always records into `tracker` first (state must accumulate across calls
/// even for domains currently below threshold -- there would be no way to
/// ever cross it otherwise), then evaluates. Three distinct situations all
/// return `None` (mirroring `dga.rs::score`'s single "not scored" `None`
/// convention rather than a `Result`):
///
/// 1. Fewer than 2 non-empty labels (`dga::split_subdomain_and_registrable`
///    itself returns `None`) -- nothing to key a domain on; `tracker` is
///    NOT touched in this case.
/// 2. `distinct_count < threshold` -- recorded, just not (yet) suspicious.
/// 3. The registrable domain's labels fail `tameng::build_alert_domain`'s
///    UTF-8 validation -- recorded (the tracker itself operates on raw
///    bytes and doesn't need UTF-8), but there is no way to produce a safe
///    `registrable_domain` display string, so the event is skipped entirely
///    rather than sent with a placeholder/lossy-decoded domain. This means
///    a domain that is otherwise over-threshold but has non-UTF-8
///    registrable-domain labels never alerts -- an accepted limitation
///    matching `dga.rs`'s and `tameng::build_alert_domain`'s own
///    established "skip, never lossy-decode" contract.
pub fn evaluate(
    tracker: &TunnelTracker,
    labels: &[&[u8]],
    qtype: u16,
    threshold: u32,
) -> Option<TunnelScore> {
    let (subdomain_labels, registrable_labels) = dga::split_subdomain_and_registrable(labels)?;

    let distinct_count = tracker.record(&registrable_labels, &subdomain_labels);

    if (distinct_count as u32) < threshold {
        return None;
    }

    let registrable_label_refs: Vec<&[u8]> = registrable_labels.iter().map(Vec::as_slice).collect();
    let registrable_domain = tameng::build_alert_domain(&registrable_label_refs)?;

    let mut reasons = vec!["high_distinct_subdomain_count"];
    reasons.extend(static_reasons(&subdomain_labels, qtype));

    // Bounded formula: see SCORE_HEADROOM_MULTIPLIER's doc comment for why
    // `* 2.0` specifically. `threshold` is validated > 0 at config load
    // (config.rs), so this division is never by zero in the deployed
    // configuration; even if it somehow were, f64 division by 0.0 yields
    // `inf`, and `.min(1.0)` still clamps the result -- no panic either way.
    let score = (distinct_count as f64 / (threshold as f64 * SCORE_HEADROOM_MULTIPLIER)).min(1.0);

    Some(TunnelScore {
        score,
        distinct_count,
        registrable_domain,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels_vec(strs: &[&[u8]]) -> Vec<Vec<u8>> {
        strs.iter().map(|s| s.to_vec()).collect()
    }

    // ---- TunnelTracker::record ----

    #[test]
    fn record_first_chain_for_a_domain_returns_one() {
        let tracker = TunnelTracker::new(10, 10);
        let registrable = labels_vec(&[b"evil", b"com"]);
        let subdomain = labels_vec(&[b"data1"]);
        assert_eq!(tracker.record(&registrable, &subdomain), 1);
    }

    #[test]
    fn record_same_chain_twice_does_not_increase_distinct_count() {
        let tracker = TunnelTracker::new(10, 10);
        let registrable = labels_vec(&[b"evil", b"com"]);
        let subdomain = labels_vec(&[b"data1"]);
        assert_eq!(tracker.record(&registrable, &subdomain), 1);
        assert_eq!(tracker.record(&registrable, &subdomain), 1);
        assert_eq!(tracker.record(&registrable, &subdomain), 1);
    }

    /// HIGH-1/HIGH-2 regression guard: the inner LRU's hash-based rewrite
    /// must still treat `[b"ab", b"c"]` and `[b"a", b"bc"]` as two DISTINCT
    /// subdomain chains, never collapsed into one, even though the inner
    /// key is now a `u64` hash rather than the raw label bytes. This is
    /// exactly the label-boundary-safety property `Vec<Vec<u8>>`'s (and
    /// `[Vec<u8>]`'s) own derived `Hash` impl already provides -- hashing
    /// length-then-bytes per label in sequence -- which the fix must reuse
    /// via `.hash()` rather than a manual concatenation. A naive
    /// concatenation (`"ab" + "c"` == `"a" + "bc"` == `"abc"`) would
    /// silently collapse these two into one entry, permanently
    /// undercounting `distinct_count` for any domain whose tunneling
    /// payload happens to straddle a label boundary differently between
    /// queries -- exactly the desync bug class `dga.rs`'s and `tameng.rs`'s
    /// own doc comments warn about for naive joins.
    #[test]
    fn record_label_boundary_split_of_same_total_bytes_are_distinct_chains() {
        let tracker = TunnelTracker::new(10, 10);
        let registrable = labels_vec(&[b"evil", b"com"]);
        let chain_a = labels_vec(&[b"ab", b"c"]);
        let chain_b = labels_vec(&[b"a", b"bc"]);
        assert_eq!(tracker.record(&registrable, &chain_a), 1);
        assert_eq!(
            tracker.record(&registrable, &chain_b),
            2,
            "label-boundary splits of the same total bytes must be tracked \
             as distinct chains, not collapsed into one -- if this is 1, \
             the hash-based rewrite has regressed into a boundary-unsafe \
             (e.g. naively concatenated) hash"
        );
        // And confirm re-recording either chain a second time still does
        // NOT grow the count further -- both are now genuinely tracked,
        // independently, as repeats of themselves.
        assert_eq!(tracker.record(&registrable, &chain_a), 2);
        assert_eq!(tracker.record(&registrable, &chain_b), 2);
    }

    #[test]
    fn record_distinct_chains_under_same_domain_increase_count() {
        let tracker = TunnelTracker::new(10, 10);
        let registrable = labels_vec(&[b"evil", b"com"]);
        assert_eq!(tracker.record(&registrable, &labels_vec(&[b"chunk1"])), 1);
        assert_eq!(tracker.record(&registrable, &labels_vec(&[b"chunk2"])), 2);
        assert_eq!(tracker.record(&registrable, &labels_vec(&[b"chunk3"])), 3);
    }

    #[test]
    fn record_different_domains_are_tracked_independently() {
        let tracker = TunnelTracker::new(10, 10);
        let domain_a = labels_vec(&[b"evil", b"com"]);
        let domain_b = labels_vec(&[b"cdn", b"example", b"net"]);
        assert_eq!(tracker.record(&domain_a, &labels_vec(&[b"chunk1"])), 1);
        assert_eq!(tracker.record(&domain_b, &labels_vec(&[b"asset1"])), 1);
        assert_eq!(tracker.record(&domain_a, &labels_vec(&[b"chunk2"])), 2);
        assert_eq!(
            tracker.record(&domain_b, &labels_vec(&[b"asset1"])),
            1,
            "domain_b's repeat of an already-seen chain must not grow, \
             independent of domain_a's count"
        );
    }

    #[test]
    fn record_count_is_bounded_by_inner_capacity() {
        // Accepted imprecision documented on `record`: pushing well past
        // inner_capacity distinct chains must plateau at inner_capacity,
        // never exceed it.
        let tracker = TunnelTracker::new(10, 5);
        let registrable = labels_vec(&[b"evil", b"com"]);
        let mut last = 0;
        for i in 0..50u32 {
            let subdomain = labels_vec(&[i.to_string().as_bytes()]);
            last = tracker.record(&registrable, &subdomain);
        }
        assert_eq!(last, 5, "distinct count must plateau at inner_capacity");
    }

    #[test]
    fn record_empty_subdomain_chain_is_a_valid_distinct_entry() {
        // A direct query for the registrable domain itself (no subdomain)
        // is a legitimate, trackable "chain" -- must not panic or behave
        // specially.
        let tracker = TunnelTracker::new(10, 10);
        let registrable = labels_vec(&[b"evil", b"com"]);
        assert_eq!(tracker.record(&registrable, &[]), 1);
        assert_eq!(tracker.record(&registrable, &[]), 1);
        assert_eq!(tracker.record(&registrable, &labels_vec(&[b"sub"])), 2);
    }

    // ---- evaluate ----

    #[test]
    fn evaluate_below_threshold_returns_none_but_still_records() {
        let tracker = TunnelTracker::new(10, 10);
        let labels: [&[u8]; 3] = [b"chunk1", b"evil", b"com"];
        assert_eq!(evaluate(&tracker, &labels, 1, 3), None);

        // Confirm it was still recorded: two more distinct chains should
        // reach the threshold on the third call.
        let labels2: [&[u8]; 3] = [b"chunk2", b"evil", b"com"];
        assert_eq!(evaluate(&tracker, &labels2, 1, 3), None);
        let labels3: [&[u8]; 3] = [b"chunk3", b"evil", b"com"];
        let score = evaluate(&tracker, &labels3, 1, 3).expect("3rd distinct chain crosses threshold=3");
        assert_eq!(score.distinct_count, 3);
    }

    #[test]
    fn evaluate_at_threshold_returns_some_with_high_distinct_count_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let labels: [&[u8]; 3] = [b"chunk1", b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1, 1).expect("threshold=1 triggers on first query");
        assert_eq!(score.distinct_count, 1);
        assert!(score.reasons.contains(&"high_distinct_subdomain_count"));
        assert_eq!(score.registrable_domain, "evil.com");
        assert!((0.0..=1.0).contains(&score.score));
    }

    #[test]
    fn evaluate_fewer_than_two_labels_returns_none_and_does_not_touch_tracker() {
        let tracker = TunnelTracker::new(10, 10);
        assert_eq!(evaluate(&tracker, &[b"localhost"], 1, 1), None);
        assert_eq!(evaluate(&tracker, &[], 1, 1), None);

        // Prove the tracker was never touched: a subsequent real domain
        // must still start its distinct count at 1, not something poisoned
        // by a prior no-op call.
        let labels: [&[u8]; 2] = [b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1, 1).unwrap();
        assert_eq!(score.distinct_count, 1);
    }

    #[test]
    fn evaluate_qtype_txt_adds_tunnel_prone_qtype_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let labels: [&[u8]; 3] = [b"chunk1", b"evil", b"com"];
        let score = evaluate(&tracker, &labels, QTYPE_TXT, 1).unwrap();
        assert!(score.reasons.contains(&"tunnel_prone_qtype"));
    }

    #[test]
    fn evaluate_qtype_null_adds_tunnel_prone_qtype_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let labels: [&[u8]; 3] = [b"chunk1", b"evil", b"com"];
        let score = evaluate(&tracker, &labels, QTYPE_NULL, 1).unwrap();
        assert!(score.reasons.contains(&"tunnel_prone_qtype"));
    }

    #[test]
    fn evaluate_ordinary_a_query_does_not_add_tunnel_prone_qtype_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let labels: [&[u8]; 3] = [b"chunk1", b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1 /* A */, 1).unwrap();
        assert!(!score.reasons.contains(&"tunnel_prone_qtype"));
    }

    #[test]
    fn evaluate_long_packed_label_adds_long_subdomain_label_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let long_label: Vec<u8> = vec![b'a'; 60]; // 60/63 > 0.8 threshold
        let labels: [&[u8]; 3] = [&long_label, b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1, 1).unwrap();
        assert!(score.reasons.contains(&"long_subdomain_label"));
    }

    #[test]
    fn evaluate_short_label_does_not_add_long_subdomain_label_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let labels: [&[u8]; 3] = [b"ab", b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1, 1).unwrap();
        assert!(!score.reasons.contains(&"long_subdomain_label"));
    }

    #[test]
    fn evaluate_high_entropy_subdomain_chain_adds_reason() {
        let tracker = TunnelTracker::new(10, 10);
        // A maximally-diverse-character subdomain chain, same style fixture
        // dga.rs's own high-entropy tests use.
        let labels: [&[u8]; 3] = [b"xkjqwzpqmnbvcxzl", b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1, 1).unwrap();
        assert!(
            score.reasons.contains(&"high_entropy_subdomain_chain"),
            "reasons: {:?}",
            score.reasons
        );
    }

    #[test]
    fn evaluate_registrable_domain_non_utf8_returns_none_even_above_threshold() {
        let tracker = TunnelTracker::new(10, 10);
        let invalid: &[u8] = &[0xFF, 0xFE];
        let labels: [&[u8]; 3] = [b"chunk1", invalid, b"com"];
        // Registrable domain here is [invalid, "com"] -- not valid UTF-8.
        assert_eq!(
            evaluate(&tracker, &labels, 1, 1),
            None,
            "non-UTF-8 registrable domain must skip the whole event, even \
             though distinct_count (1) is at/above threshold (1)"
        );
    }

    #[test]
    fn evaluate_non_utf8_subdomain_label_does_not_panic_and_skips_entropy_reason() {
        let tracker = TunnelTracker::new(10, 10);
        let invalid: &[u8] = &[0xFF, 0xFE];
        let labels: [&[u8]; 3] = [invalid, b"evil", b"com"];
        let score = evaluate(&tracker, &labels, 1, 1)
            .expect("registrable domain (evil.com) is valid UTF-8, so this must still score");
        assert!(!score.reasons.contains(&"high_entropy_subdomain_chain"));
    }

    #[test]
    fn evaluate_score_is_bounded_and_reaches_one_at_headroom_multiplier() {
        let tracker = TunnelTracker::new(10, 200);
        let threshold = 5u32;
        // Push distinct_count up to exactly threshold * SCORE_HEADROOM_MULTIPLIER.
        let target = (threshold as f64 * SCORE_HEADROOM_MULTIPLIER) as u32;
        let mut last_score = None;
        for i in 0..target {
            let subdomain = format!("chunk{i}");
            let labels: [&[u8]; 3] = [subdomain.as_bytes(), b"evil", b"com"];
            last_score = evaluate(&tracker, &labels, 1, threshold);
        }
        let score = last_score.expect("well above threshold by the final iteration");
        assert!((score.score - 1.0).abs() < 1e-9, "score={}", score.score);
    }

    #[test]
    fn evaluate_score_never_exceeds_one_far_past_headroom() {
        let tracker = TunnelTracker::new(10, 500);
        let threshold = 2u32;
        let mut last_score = None;
        for i in 0..400u32 {
            let subdomain = format!("chunk{i}");
            let labels: [&[u8]; 3] = [subdomain.as_bytes(), b"evil", b"com"];
            last_score = evaluate(&tracker, &labels, 1, threshold);
        }
        let score = last_score.unwrap();
        assert!((0.0..=1.0).contains(&score.score));
    }

    /// Panic-safety fuzz sweep, analogous to dga.rs's own
    /// `no_panic_on_adversarial_raw_label_bytes`, driving `evaluate`
    /// directly (not just the lower-level helpers) across a large number of
    /// adversarial and pseudo-random wire-format label sets. Zero panics is
    /// the only thing asserted -- `query_name`/labels are fully
    /// attacker-controlled and this crate builds with `panic = "abort"` in
    /// release, so any panic here would kill DNS resolution for every
    /// in-flight query, not just this one.
    #[test]
    fn no_panic_on_adversarial_tunnel_input() {
        let tracker = TunnelTracker::new(50, 50);

        let all_ff_63: Vec<u8> = vec![0xFFu8; 63];
        let with_nul: Vec<u8> = vec![b'a', 0x00, b'b', 0x00, b'c'];
        let single_byte: Vec<u8> = vec![0x01];
        let empty: Vec<u8> = vec![];
        let mixed_invalid_utf8: Vec<u8> = vec![0xC0, 0xC1, 0xF5, 0xFF, 0xFE];
        let max_label: Vec<u8> = vec![b'z'; 63];
        // Near the 253-byte wire-name maximum: four 63-byte labels (252
        // bytes) + a trailing "co" (2 bytes) = 254 raw content bytes
        // (length prefixes are not counted in this in-memory
        // representation, only in the real wire encoding, but this still
        // exercises the length-ratio math near/at its ceiling).
        let near_max_labels: Vec<&[u8]> =
            vec![&max_label, &max_label, &max_label, &max_label, b"co"];

        let candidate_label_sets: Vec<Vec<&[u8]>> = vec![
            vec![],
            vec![b""],
            vec![&empty, &empty],
            vec![&all_ff_63, b"com"],
            vec![&with_nul, b"evil", b"com"],
            vec![&single_byte],
            vec![&mixed_invalid_utf8, &mixed_invalid_utf8, b"com"],
            vec![&mixed_invalid_utf8, b"evil", b"com"],
            vec![b"evil", &mixed_invalid_utf8, b"com"],
            near_max_labels,
            vec![b"a"; 40], // deeply nested many-label name
            vec![b"co", b"uk"],
            vec![b"evil", b"co", b"uk"],
            vec![b"", b"", b"evil", b"", b"com", b""],
        ];

        for qtype in [1u16, QTYPE_TXT, QTYPE_NULL, 65535u16] {
            for labels in &candidate_label_sets {
                for threshold in [0u32, 1, 30, u32::MAX] {
                    let _ = evaluate(&tracker, labels, qtype, threshold);
                }
            }
        }

        // A long pseudo-random sweep of generated label sets, varying
        // length/byte-content deterministically (no external RNG
        // dependency needed for a smoke sweep like this).
        let mut seed: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..500 {
            let num_labels = 1 + (next() % 8) as usize;
            let mut owned_labels: Vec<Vec<u8>> = Vec::with_capacity(num_labels);
            for _ in 0..num_labels {
                let len = (next() % 64) as usize;
                let bytes: Vec<u8> = (0..len).map(|_| (next() % 256) as u8).collect();
                owned_labels.push(bytes);
            }
            let refs: Vec<&[u8]> = owned_labels.iter().map(Vec::as_slice).collect();
            let qtype = (next() % 65536) as u16;
            let threshold = (next() % 100) as u32;
            let _ = evaluate(&tracker, &refs, qtype, threshold);
        }
    }
}
