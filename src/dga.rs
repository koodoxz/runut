//! DGA (Domain Generation Algorithm) heuristic detection.
//!
//! Scores a queried domain name for DGA-like characteristics using
//! lightweight, dependency-free heuristics (entropy, consonant runs, digit
//! ratio, vowel ratio, length) rather than a trained classifier -- no
//! wordlist/model shipped, alert-only, no blocking capability in this REQ.
//!
//! Scores the registrable label (the label immediately before the last one,
//! e.g. "example" in "www.example.com.") specifically to avoid
//! false-positiving on legitimate but random-looking CDN/cloud subdomains
//! (e.g. "d1a2b3c4.cloudfront.net" scores on "cloudfront", not "d1a2b3c4").
//! ponytail: subdomain-level scoring (needed for DNS-tunneling detection,
//! not DGA) is a separate, already-built feature -- see `tunnel.rs`, REQ
//! RUNUT-DNS-TUNNEL-DETECT-001.
//!
//! Operates on raw wire-format DNS label bytes (e.g. from iterating a
//! `trust_dns_proto::rr::Name`), not a pre-formatted display string -- see
//! `score`'s doc comment for why a display string is unsafe here. This
//! module intentionally has no dependency on `trust_dns_proto` itself: it
//! only needs `&[u8]` label slices, which keeps the heuristics testable in
//! isolation and keeps this module's stated "dependency-free" property
//! about the scoring logic, not just the absence of a wordlist/model.

use std::collections::HashMap;

/// A DGA suspicion score in [0.0, 1.0] plus the reasons that contributed to
/// it, for logging.
#[derive(Debug, Clone, PartialEq)]
pub struct DgaScore {
    pub score: f64,
    pub label: String,
    pub reasons: Vec<&'static str>,
}

/// Known multi-label public suffixes where the registrable label sits one
/// level deeper than a naive last-two-labels split would find (e.g. "evil"
/// in "evil.co.uk.", not "co"). Not a full Public Suffix List -- that's
/// either a network fetch or embedding Mozilla's ~15k-entry PSL as a new
/// dependency, out of scope for this heuristic detector. A small hardcoded
/// set covering the common cases found in review; a DGA domain registered
/// under an unlisted multi-label suffix still evades this check (documented
/// limitation, not fixed).
const KNOWN_MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "com.br", "com.cn",
    "co.jp", "co.id", "co.in", "co.nz", "com.sg", "com.mx",
];

/// Size of the alphabet DGA-style random labels are typically drawn from:
/// lowercase letters + digits (26 + 10 = 36). Used only to compute the
/// length-appropriate entropy ceiling in `entropy_ratio` below -- it does
/// not restrict which characters are actually scored.
const DGA_ALPHABET_SIZE: usize = 36;

/// True if `second_last`.`last` (e.g. `co`.`uk`) matches one of the known
/// multi-label suffixes, compared byte-for-byte case-insensitively so no
/// intermediate display string or dotted reassembly is needed.
fn matches_known_multi_label_suffix(second_last: &[u8], last: &[u8]) -> bool {
    KNOWN_MULTI_LABEL_SUFFIXES.iter().any(|suffix| {
        let Some((first_part, second_part)) = suffix.split_once('.') else {
            return false;
        };
        second_last.eq_ignore_ascii_case(first_part.as_bytes())
            && last.eq_ignore_ascii_case(second_part.as_bytes())
    })
}

/// Extracts the registrable label to score from raw wire-format DNS label
/// bytes (most-specific label first), e.g. `[b"www", b"example", b"com"]`
/// -> `b"example"`, or `[b"evil", b"co", b"uk"]` -> `b"evil"` (not `b"co"`)
/// via the known-suffix list above.
///
/// Operating on labels exactly as they arrived on the wire -- rather than a
/// display-formatted string -- means there is no dot delimiter to desync
/// and no IDNA/punycode unescaping step for an attacker to exploit; see
/// `score`'s doc comment for the concrete vulnerability this avoids.
///
/// Returns None for fewer than 2 non-empty labels (nothing identifiable to
/// score) -- callers treat this as "not scored", not zero/safe. The
/// returned label bytes are ASCII-lowercased (DNS labels are ASCII
/// case-insensitive); non-ASCII bytes are left untouched.
fn registrable_label(labels: &[&[u8]]) -> Option<Vec<u8>> {
    let labels: Vec<&[u8]> = labels.iter().copied().filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }

    if labels.len() >= 3 {
        let last = labels[labels.len() - 1];
        let second_last = labels[labels.len() - 2];
        if matches_known_multi_label_suffix(second_last, last) {
            let label = labels[labels.len() - 3];
            if !label.is_empty() {
                let mut owned = label.to_vec();
                owned.make_ascii_lowercase();
                return Some(owned);
            }
        }
    }

    let label = labels[labels.len() - 2];
    let mut owned = label.to_vec();
    owned.make_ascii_lowercase();
    Some(owned)
}

/// Splits raw wire-format DNS label bytes into (subdomain labels,
/// registrable domain), using the same known-multi-label-suffix logic as
/// `registrable_label` above (does not duplicate `KNOWN_MULTI_LABEL_SUFFIXES`
/// or `matches_known_multi_label_suffix`). "Subdomain labels" is everything
/// more specific than the registrable domain, most-specific label first --
/// for `[b"data1", b"aGVsbG8", b"evil", b"com"]` this returns
/// (`[b"data1", b"agvsbg8"]`, `[b"evil", b"com"]`). Returns `None` under the
/// same conditions `registrable_label` does (fewer than 2 non-empty labels).
///
/// Built for REQ RUNUT-DNS-TUNNEL-DETECT-001 (see tunnel.rs), which needs to
/// key a per-domain tracker on the registrable domain while separately
/// hashing the more-specific subdomain chain above it.
///
/// # Why the registrable domain is `Vec<Vec<u8>>`, not a joined `Vec<u8>`
///
/// A dot-joined byte string was considered and rejected. `dga.rs`'s own
/// `score` and `tameng::build_alert_domain` both have extensive doc
/// comments/regression tests establishing that joining raw wire-format
/// labels with a literal `.` byte is unsafe in general: RFC 1035 labels are
/// length-prefixed, not dot-delimited, so a literal `.` (or `\`) byte
/// legally inside ONE label is indistinguishable from a real label-boundary
/// separator once joined, unless it is escaped first (which is exactly what
/// `build_alert_domain` does for *display/logging* purposes). Reusing that
/// escaping here just to build an internal map key would be solving a
/// problem this function doesn't have: `Vec<Vec<u8>>` is `Hash + Eq` with no
/// join step at all, so each element unambiguously round-trips as exactly
/// the label it came from -- no delimiter, no escaping, no desync surface.
/// Callers that need a safe *display* string for logging (e.g.
/// `tunnel::evaluate`) still go through `tameng::build_alert_domain`
/// separately for that purpose.
///
/// Both the subdomain and registrable label bytes returned are
/// ASCII-lowercased (DNS labels are ASCII case-insensitive, matching
/// `registrable_label`'s own behavior) -- this keeps `0x20`-style
/// case-randomized queries for the same logical name from being counted as
/// artificially distinct by `tunnel::TunnelTracker`.
pub(crate) fn split_subdomain_and_registrable(labels: &[&[u8]]) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let filtered: Vec<&[u8]> = labels.iter().copied().filter(|l| !l.is_empty()).collect();
    if filtered.len() < 2 {
        return None;
    }

    // Same decision `registrable_label` makes: 3 trailing labels form the
    // registrable domain when the known multi-label-suffix pattern matches
    // (e.g. "evil.co.uk"), otherwise 2 (the common case, e.g.
    // "example.com"). `registrable_len` is always <= filtered.len() here:
    // when filtered.len() == 2 the suffix branch is skipped entirely (it
    // requires >= 3 to even check), so registrable_len stays 2.
    let registrable_len = if filtered.len() >= 3 {
        let last = filtered[filtered.len() - 1];
        let second_last = filtered[filtered.len() - 2];
        if matches_known_multi_label_suffix(second_last, last) {
            3
        } else {
            2
        }
    } else {
        2
    };
    let split_at = filtered.len() - registrable_len;

    let lowercase = |label: &&[u8]| {
        let mut owned = label.to_vec();
        owned.make_ascii_lowercase();
        owned
    };
    let subdomain_labels: Vec<Vec<u8>> = filtered[..split_at].iter().map(lowercase).collect();
    let registrable_labels: Vec<Vec<u8>> = filtered[split_at..].iter().map(lowercase).collect();

    Some((subdomain_labels, registrable_labels))
}

/// Shannon entropy of `s`, in bits per character over the character
/// frequency distribution. `pub(crate)`: reused directly by
/// `tunnel::evaluate` (RUNUT-DNS-TUNNEL-DETECT-001) to avoid a second copy
/// of this math -- see this file's module doc comment for why
/// tunnel-detection was deliberately kept out of the original DGA REQ, and
/// tunnel.rs for why it computes entropy over the full concatenated
/// subdomain chain rather than a single label.
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// Shannon entropy of `s`, normalized against the maximum entropy
/// structurally achievable by a label of `len` characters drawn from a
/// `DGA_ALPHABET_SIZE`-symbol alphabet (`log2(min(len, DGA_ALPHABET_SIZE))`),
/// instead of compared to a fixed absolute bound.
///
/// Problem this fixes: the module's original heuristic required raw
/// entropy > 3.5 bits/char, which needs >= 12 distinct characters to ever
/// be reached (2^3.5 ~= 11.3) -- structurally impossible for labels shorter
/// than 12 characters no matter how random they are. Several real DGA
/// families use 8-11 character labels and would never trip this signal at
/// all, regardless of how much of their own achievable entropy they
/// carried. It also means the old flat 3.5-bit bar implicitly assumed
/// near-full 36-symbol diversity was reachable regardless of length, which
/// is false for short labels and, it turns out, overly lenient for
/// medium-length ones too.
///
/// Normalizing against each label's own length-appropriate ceiling fixes
/// both: at `len == DGA_ALPHABET_SIZE` (36) this ceiling equals
/// `log2(36)`, so the trigger ratio used in `score` (`3.5 / log2(36)`) is
/// carried over directly from the original absolute threshold rather than
/// a newly hand-picked number -- it is the same bar, just expressed
/// relative to what is achievable at that length. Shorter labels get a
/// proportionally lower absolute bar, which is the intended fix.
///
/// `pub(crate)`: reused directly by `tunnel::evaluate`
/// (RUNUT-DNS-TUNNEL-DETECT-001) for the same length-scaled-ceiling reason
/// this was originally written for, applied to a subdomain chain instead of
/// a single registrable label -- see `shannon_entropy`'s doc comment.
pub(crate) fn entropy_ratio(s: &str, len: usize) -> f64 {
    if len < 2 {
        return 0.0;
    }
    let max_entropy = (len.min(DGA_ALPHABET_SIZE) as f64).log2();
    if max_entropy <= 0.0 {
        return 0.0;
    }
    shannon_entropy(s) / max_entropy
}

/// Trigger ratio for `entropy_ratio`, derived from (not replacing) the
/// module's original absolute threshold: `3.5 / log2(DGA_ALPHABET_SIZE)`.
/// Computed rather than hardcoded to avoid a second, drift-prone copy of
/// the derivation living next to the comment that explains it.
///
/// `pub(crate)`: reused directly by `tunnel::evaluate`
/// (RUNUT-DNS-TUNNEL-DETECT-001) as the trigger bar for its own
/// `high_entropy_subdomain_chain` corroborating reason, rather than a second
/// independently-hand-picked threshold living next to this one.
pub(crate) fn high_entropy_ratio_threshold() -> f64 {
    3.5 / (DGA_ALPHABET_SIZE as f64).log2()
}

fn longest_consonant_run(s: &str) -> usize {
    let is_vowel = |c: char| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u');
    let mut longest = 0usize;
    let mut current = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphabetic() && !is_vowel(c) {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn digit_ratio(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    digits as f64 / s.chars().count() as f64
}

/// Vowel ratio over alphabetic characters only. Returns 1.0 (neutral, not
/// suspicious for this specific signal) when the label has no letters at
/// all -- a purely numeric label isn't what this heuristic is measuring.
fn vowel_ratio(s: &str) -> f64 {
    let alpha: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if alpha.is_empty() {
        return 1.0;
    }
    let vowels = alpha
        .iter()
        .filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    vowels as f64 / alpha.len() as f64
}

/// Scores a queried domain name for DGA-like characteristics.
///
/// Takes raw wire-format DNS label byte slices, most-specific label first
/// (e.g. `name.iter().collect::<Vec<&[u8]>>()` on a
/// `trust_dns_proto::rr::Name`) -- NOT a pre-formatted display string.
///
/// # Why raw label bytes, not `Name::to_string()`
///
/// `query_name` is fully attacker-controlled, and this crate builds with
/// `panic = "abort"` in release, so correctness here matters beyond just
/// detection quality. Scoring a `Name`'s display string (its `.to_string()`
/// / `Display` form) was found, under review, to be exploitable two ways:
///
/// 1. `trust-dns` IDNA-decodes `xn--`-prefixed labels to raw Unicode in the
///    display string *without escaping*. If the decoded text happens to
///    contain a literal `.`, a naive `split('.')` desyncs.
/// 2. Even without punycode: RFC 1035 labels are length-prefixed on the
///    wire, not dot-delimited, so a literal `.` byte (0x2E) inside a single
///    label is perfectly legal. `Name`'s non-IDNA display path escapes it
///    as `\.`, but that escape is just two more characters to a naive
///    `split('.')` -- it still desyncs, letting an attacker fragment one
///    label into several (diluting a genuinely suspicious label's score
///    below threshold) or manufacture extra low-entropy "labels" to shift
///    which piece gets treated as registrable.
///
/// Working directly from wire-format label bytes has neither problem: each
/// element of `labels` is already exactly one label, with no delimiter to
/// desync and no display-formatting step to exploit.
///
/// # Non-UTF-8 registrable labels
///
/// DNS labels are arbitrary bytes with no charset guarantee. The heuristics
/// below (entropy, vowel/consonant counting) are defined over Unicode
/// scalar values and have no principled byte-level equivalent, so if the
/// registrable label's raw bytes are not valid UTF-8, `score` returns
/// `None` ("not scored", the same contract as the fewer-than-2-labels
/// case) rather than lossily decoding. Lossy decoding
/// (`String::from_utf8_lossy`) would replace invalid sequences with a
/// fixed placeholder character under attacker control of *how many* and
/// *where* -- the same class of score-manufacturing this rewrite exists to
/// close -- so it is not used here.
///
/// Returns None if the domain has no identifiable registrable label (fewer
/// than 2 labels) or that label is not valid UTF-8.
pub fn score(labels: &[&[u8]]) -> Option<DgaScore> {
    let label_bytes = registrable_label(labels)?;
    let label = std::str::from_utf8(&label_bytes).ok()?.to_string();
    let len = label.chars().count();

    let mut total: f64 = 0.0;
    let mut reasons = Vec::new();

    // See `entropy_ratio`'s doc comment for why this is normalized against
    // each label's own length-appropriate ceiling rather than compared to
    // a fixed absolute bound.
    if entropy_ratio(&label, len) > high_entropy_ratio_threshold() {
        total += 0.35;
        reasons.push("high_entropy");
    }

    // Long consonant runs are rare in pronounceable words/brand names but
    // common in randomly generated strings.
    //
    // Weight raised from 0.25 (was: paired with low_vowel_ratio's original
    // 0.2, summing to 0.45 -- structurally unable to cross the 0.5 default
    // threshold no matter how strong both signals were). Review measured
    // several real DGA families (Conficker, Necurs, Cryptolocker, Tinba,
    // Pykspa, Nymaim, Locky) landing at exactly that 0.45 ceiling. Raised
    // together with low_vowel_ratio below so their combination alone (0.55)
    // now crosses the threshold -- a deliberate, targeted fix for that
    // specific structural gap, not a broader corpus-validated retune.
    if longest_consonant_run(&label) >= 5 {
        total += 0.3;
        reasons.push("long_consonant_run");
    }

    if digit_ratio(&label) > 0.3 {
        total += 0.2;
        reasons.push("high_digit_ratio");
    }

    if vowel_ratio(&label) < 0.2 {
        total += 0.25;
        reasons.push("low_vowel_ratio");
    }

    if len >= 20 {
        total += 0.1;
        reasons.push("unusually_long_label");
    }

    Some(DgaScore {
        score: total.min(1.0),
        label,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::rr::Name;

    /// Test-only convenience: builds label byte-slices from a plain dotted
    /// ASCII domain string and calls `score`. Safe for hardcoded test
    /// fixtures (no embedded escapes or literal dots-within-a-label -- the
    /// exact assumption that made the old production `score(&str)` API
    /// unsafe against real, attacker-controlled `Name`s; see `score`'s doc
    /// comment). Never use this string-splitting pattern on real query
    /// input.
    fn score_str(domain: &str) -> Option<DgaScore> {
        let trimmed = domain.trim_end_matches('.');
        let labels: Vec<&[u8]> = trimmed.split('.').map(str::as_bytes).collect();
        score(&labels)
    }

    #[test]
    fn legit_brand_domains_score_low() {
        for domain in [
            "google.com.",
            "www.google.com.",
            "amazon.com.",
            "d1a2b3c4.cloudfront.net.", // random-looking subdomain, legit SLD
            "github.com.",
        ] {
            let s = score_str(domain).expect("2+ labels should always score");
            assert!(
                s.score < 0.5,
                "{domain} scored {} (label={:?}, reasons={:?}), want <0.5",
                s.score,
                s.label,
                s.reasons
            );
        }
    }

    #[test]
    fn dga_like_domains_score_high() {
        for domain in ["xkjqwzpqmnbvcxzl.com.", "a1b2c3d4e5f6g7h8.net."] {
            let s = score_str(domain).expect("2+ labels should always score");
            assert!(
                s.score >= 0.5,
                "{domain} scored {} (label={:?}, reasons={:?}), want >=0.5",
                s.score,
                s.label,
                s.reasons
            );
        }
    }

    #[test]
    fn multi_label_suffix_scores_the_real_registrable_label_not_the_suffix() {
        // Regression guard: "evil.co.uk." must score "evil", not "co" --
        // the naive last-two-labels split picked "co" (score 0.0), a
        // trivial evasion for any DGA registered under .co.uk/.com.br/etc.
        let s = score_str("hjfgqhwjeqmqevqk.co.uk.").unwrap();
        assert_eq!(s.label, "hjfgqhwjeqmqevqk");
        assert!(
            s.score >= 0.5,
            "expected the real label to score high, got {} (label={:?})",
            s.score,
            s.label
        );

        // A plain suffix domain itself (no label deeper than the suffix)
        // must not panic and falls back to scoring "co" -- low stakes, no
        // real registrable label exists to score here.
        assert!(score_str("co.uk.").is_some());
    }

    #[test]
    fn cloudfront_subdomain_does_not_leak_into_scored_label() {
        // Regression guard for the specific false-positive class this
        // module is designed to avoid: a random-looking CDN subdomain must
        // not be what gets scored.
        let s = score_str("d1a2b3c4d5e6f7.cloudfront.net.").unwrap();
        assert_eq!(s.label, "cloudfront");
    }

    #[test]
    fn single_label_returns_none() {
        assert_eq!(score_str("localhost"), None);
        assert_eq!(score_str("localhost."), None);
    }

    #[test]
    fn root_query_returns_none() {
        assert_eq!(score_str("."), None);
        assert_eq!(score_str(""), None);
    }

    #[test]
    fn no_panic_on_adversarial_input() {
        // query_name is fully attacker-controlled; this crate builds with
        // panic = "abort" in release, so a panic here would crash the
        // entire resolver process for every in-flight query, not just this
        // one -- these inputs must never panic.
        let adversarial = [
            "..",
            "...",
            "a..b.com.",
            ".com.",
            "\u{1F980}\u{1F980}\u{1F980}.com.",
            &"a".repeat(300),
            &format!("{}.com.", "x".repeat(300)),
        ];
        for input in adversarial {
            let _ = score_str(input);
        }
    }

    /// Item 3 panic-safety sweep, operating on the new raw-bytes entry
    /// point directly (not the `score_str` string-splitting test helper):
    /// empty labels, single-byte labels, all-0xFF bytes, embedded NUL
    /// bytes, and maximum-length (255 total wire-name budget, so 63-byte
    /// max single-label per RFC 1035) label content. None of these are
    /// valid UTF-8 in general, exercising the "not scoreable" None path
    /// as well as the scoreable path where they happen to decode.
    #[test]
    fn no_panic_on_adversarial_raw_label_bytes() {
        let all_ff_63: Vec<u8> = vec![0xFFu8; 63];
        let with_nul: Vec<u8> = vec![b'a', 0x00, b'b', 0x00, b'c'];
        let single_byte: Vec<u8> = vec![0x01];
        let empty: Vec<u8> = vec![];
        let mixed_invalid_utf8: Vec<u8> = vec![0xC0, 0xC1, 0xF5, 0xFF, 0xFE];

        let candidate_labels: Vec<&[u8]> = vec![
            &all_ff_63,
            &with_nul,
            &single_byte,
            &empty,
            &mixed_invalid_utf8,
            b"com",
            b"",
            b"a",
        ];

        // Every 2-permutation-ish grouping we can cheaply build, not just
        // the full list, since registrable_label's behavior depends on
        // exactly which labels are adjacent/last.
        let _ = score(&candidate_labels);
        let _ = score(&[&all_ff_63, b"com"]);
        let _ = score(&[&with_nul, b"com"]);
        let _ = score(&[&single_byte]);
        let _ = score(&[&empty, &empty]);
        let _ = score(&[&mixed_invalid_utf8, &mixed_invalid_utf8, b"com"]);
        let _ = score(&[]);
        let _ = score(&[b""]);
    }

    #[test]
    fn purely_numeric_label_does_not_panic_on_vowel_ratio() {
        // vowel_ratio's empty-alpha branch: a label with digits only.
        let s = score_str("12345.com.").unwrap();
        assert!(s.score.is_finite());
    }

    #[test]
    fn score_is_always_clamped_to_one() {
        // Longest possible label hitting every heuristic at once must not
        // exceed the documented [0.0, 1.0] range.
        let s = score_str("bcdfghjklmnpqrstvwxyzbcdfghjklmnpqrstvwxyz1234567890.com.").unwrap();
        assert!((0.0..=1.0).contains(&s.score));
    }

    #[test]
    fn non_utf8_registrable_label_is_not_scored() {
        // Invalid UTF-8 bytes for the registrable label -> None ("not
        // scored"), never a lossily-decoded guess. See `score`'s doc
        // comment on why lossy decoding is unsafe here.
        let invalid_utf8: &[u8] = &[0xC3, 0x28]; // malformed 2-byte UTF-8 sequence
        let labels: [&[u8]; 2] = [invalid_utf8, b"com"];
        assert_eq!(score(&labels), None);
    }

    #[test]
    fn raw_label_with_literal_dot_byte_does_not_desync_like_display_string_would() {
        // RFC 1035 labels are length-prefixed on the wire, not
        // dot-delimited -- any byte value, including a literal '.'
        // (0x2E), is legal inside a single label. Build a Name with
        // exactly 2 raw wire-format labels where the first one embeds a
        // literal dot byte partway through what is, on the wire, one
        // label.
        let evil_label: &[u8] = b"xqzjkvwb.nmpqr";
        let name = Name::from_labels(vec![evil_label, b"com".as_slice()])
            .expect("raw label bytes are valid: 1-63 bytes each, no escaping required");

        // Prove the underlying vulnerability class this rewrite closes:
        // trust-dns's Display/to_string() form does not preserve the wire
        // label boundary in a way a naive dot-splitter can recover. The
        // embedded byte renders as an indistinguishable extra '.' (either
        // raw, via IDNA-decoded punycode, or backslash-escaped -- either
        // way a bare `split('.')` cannot tell it apart from the real
        // separator), so a naive split sees 3 pieces for what is actually
        // 2 wire-format labels.
        let display = name.to_string();
        let naive_split_count = display.trim_end_matches('.').split('.').count();
        assert_ne!(
            naive_split_count,
            2,
            "expected the display string {display:?} to desync from the \
             true 2-label wire structure -- that desync is exactly the \
             bug this rewrite fixes; got a matching count, so this label \
             no longer demonstrates it"
        );

        // The new raw-bytes entry point is immune: it sees exactly the 2
        // real wire-format labels (via `Name::iter()`, never
        // `Name::to_string()`) and scores the true single label --
        // literal dot byte included, since it is genuinely part of one
        // label's content -- as one unit, not fragments of it.
        let raw_labels: Vec<&[u8]> = name.iter().collect();
        assert_eq!(raw_labels.len(), 2, "sanity check: 2 real wire labels");
        let s = score(&raw_labels).expect("2 labels should always score");
        assert_eq!(
            s.label.as_bytes(),
            evil_label,
            "the registrable label scored must be the full, un-fragmented \
             wire-format label, not a piece a naive splitter would see"
        );
    }

    // ---- split_subdomain_and_registrable (RUNUT-DNS-TUNNEL-DETECT-001) ----
    // Written before the implementation (TDD red phase) -- see this file's
    // module doc comment for why tunnel detection was deliberately deferred
    // out of the original DGA REQ, and tunnel.rs's module doc comment for
    // the full distinct-subdomain-count design this function feeds.

    #[test]
    fn split_basic_three_label_domain() {
        let labels: [&[u8]; 3] = [b"www", b"example", b"com"];
        let (subdomain, registrable) = split_subdomain_and_registrable(&labels).unwrap();
        assert_eq!(subdomain, vec![b"www".to_vec()]);
        assert_eq!(registrable, vec![b"example".to_vec(), b"com".to_vec()]);
    }

    #[test]
    fn split_multi_label_suffix_puts_everything_in_registrable() {
        // "evil.co.uk." -- the known multi-label-suffix case. Registrable
        // domain is all 3 labels; nothing left over as "subdomain".
        let labels: [&[u8]; 3] = [b"evil", b"co", b"uk"];
        let (subdomain, registrable) = split_subdomain_and_registrable(&labels).unwrap();
        assert!(subdomain.is_empty());
        assert_eq!(
            registrable,
            vec![b"evil".to_vec(), b"co".to_vec(), b"uk".to_vec()]
        );
    }

    #[test]
    fn split_four_plus_labels_with_real_subdomain_data() {
        // Matches the exact example in the REQ spec:
        // [data1, aGVsbG8, evil, com] -> subdomain=[data1, aGVsbG8],
        // registrable=[evil, com]. "evil.com" is not a known multi-label
        // suffix, so the split falls back to the last 2 labels.
        let labels: [&[u8]; 4] = [b"data1", b"aGVsbG8", b"evil", b"com"];
        let (subdomain, registrable) = split_subdomain_and_registrable(&labels).unwrap();
        assert_eq!(
            subdomain,
            vec![b"data1".to_vec(), b"agvsbg8".to_vec()],
            "subdomain labels should be lowercased, most-specific first"
        );
        assert_eq!(registrable, vec![b"evil".to_vec(), b"com".to_vec()]);
    }

    #[test]
    fn split_many_label_tunneling_style_chain() {
        // A longer, more realistic tunneling-style chain of subdomain
        // labels under one registrable domain.
        let labels: [&[u8]; 6] = [
            b"aGVsbG8gd29ybGQ",
            b"c2Vjb25kY2h1bms",
            b"dGhpcmRjaHVuaw",
            b"Zm91cnRoY2h1bms",
            b"attacker",
            b"com",
        ];
        let (subdomain, registrable) = split_subdomain_and_registrable(&labels).unwrap();
        assert_eq!(subdomain.len(), 4);
        assert_eq!(registrable, vec![b"attacker".to_vec(), b"com".to_vec()]);
    }

    #[test]
    fn split_returns_none_for_fewer_than_two_labels() {
        assert_eq!(split_subdomain_and_registrable(&[]), None);
        assert_eq!(split_subdomain_and_registrable(&[b"localhost"]), None);
        assert_eq!(split_subdomain_and_registrable(&[b""]), None);
    }

    #[test]
    fn split_two_label_domain_has_no_subdomain() {
        // No label deeper than the registrable domain itself.
        let labels: [&[u8]; 2] = [b"example", b"com"];
        let (subdomain, registrable) = split_subdomain_and_registrable(&labels).unwrap();
        assert!(subdomain.is_empty());
        assert_eq!(registrable, vec![b"example".to_vec(), b"com".to_vec()]);
    }

    #[test]
    fn split_does_not_panic_on_adversarial_raw_label_bytes() {
        // Mirrors `no_panic_on_adversarial_raw_label_bytes` above, applied
        // to the new entry point.
        let all_ff_63: Vec<u8> = vec![0xFFu8; 63];
        let with_nul: Vec<u8> = vec![b'a', 0x00, b'b', 0x00, b'c'];
        let empty: Vec<u8> = vec![];
        let mixed_invalid_utf8: Vec<u8> = vec![0xC0, 0xC1, 0xF5, 0xFF, 0xFE];

        let candidate_labels: Vec<&[u8]> = vec![
            &all_ff_63,
            &with_nul,
            &empty,
            &mixed_invalid_utf8,
            b"com",
            b"",
            b"a",
        ];

        let _ = split_subdomain_and_registrable(&candidate_labels);
        let _ = split_subdomain_and_registrable(&[&all_ff_63, b"com"]);
        let _ = split_subdomain_and_registrable(&[&with_nul, &with_nul, &with_nul, b"co", b"uk"]);
        let _ = split_subdomain_and_registrable(&[&empty, &empty]);
        let _ = split_subdomain_and_registrable(&[]);
        let _ = split_subdomain_and_registrable(&[b""]);
    }

    #[test]
    fn short_dga_style_label_triggers_entropy_signal_under_length_scaled_threshold() {
        // A short (9-char), consonant-heavy, maximally-distinct-character
        // label -- representative of real DGA families that use 8-11
        // character labels (documented gap, see `entropy_ratio`'s doc
        // comment). Under the OLD absolute >3.5-bit threshold this could
        // never trigger the entropy signal alone: log2(9) ~= 3.17 bits is
        // the theoretical per-character ceiling for a label this short
        // even with every character distinct, structurally below 3.5.
        let label = "bzkqjxwnf";
        assert_eq!(label.chars().count(), 9, "sanity check on fixture length");
        assert!(
            shannon_entropy(label) < 3.5,
            "sanity check: this label's raw entropy ({:.3} bits) must be \
             unreachable under the old absolute >3.5 threshold, or this \
             test no longer demonstrates the gap being fixed",
            shannon_entropy(label)
        );

        let labels: [&[u8]; 2] = [label.as_bytes(), b"com"];
        let s = score(&labels).expect("2 labels should always score");
        assert!(
            s.reasons.contains(&"high_entropy"),
            "expected the new length-scaled threshold to trigger \
             high_entropy for a maximally-diverse {}-char label, got \
             score={} reasons={:?}",
            label.len(),
            s.score,
            s.reasons
        );
    }
}
