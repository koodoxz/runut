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
//! not DGA) is a separate, not-yet-built feature -- see REQ
//! MIMIR-DNS-TUNNEL-DETECT-001 (not started).

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

/// Extracts the registrable label to score, e.g. "example" from
/// "www.example.com.", or "evil" (not "co") from "evil.co.uk." via the
/// known-suffix list above. Returns None for fewer than 2 non-empty labels
/// (nothing identifiable to score) -- callers treat this as "not scored",
/// not zero/safe.
fn registrable_label(domain: &str) -> Option<String> {
    let trimmed = domain.trim_end_matches('.');
    let labels: Vec<&str> = trimmed.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }

    if labels.len() >= 3 {
        let last_two = format!(
            "{}.{}",
            labels[labels.len() - 2],
            labels[labels.len() - 1]
        )
        .to_ascii_lowercase();
        if KNOWN_MULTI_LABEL_SUFFIXES.contains(&last_two.as_str()) {
            let label = labels[labels.len() - 3];
            if !label.is_empty() {
                return Some(label.to_ascii_lowercase());
            }
        }
    }

    let label = labels[labels.len() - 2];
    if label.is_empty() {
        return None;
    }
    Some(label.to_ascii_lowercase())
}

fn shannon_entropy(s: &str) -> f64 {
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

/// Scores a queried domain name for DGA-like characteristics. Returns None
/// if the domain has no identifiable registrable label (fewer than 2
/// labels) -- there is nothing to score, this is not the same as a score of
/// 0.0.
pub fn score(domain: &str) -> Option<DgaScore> {
    let label = registrable_label(domain)?;
    let len = label.chars().count();

    let mut total: f64 = 0.0;
    let mut reasons = Vec::new();

    // Real words/brand names rarely exceed ~3.3 bits/char over a short
    // label; random alnum strings approach log2(36) ~= 5.17.
    if shannon_entropy(&label) > 3.5 {
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

    #[test]
    fn legit_brand_domains_score_low() {
        for domain in [
            "google.com.",
            "www.google.com.",
            "amazon.com.",
            "d1a2b3c4.cloudfront.net.", // random-looking subdomain, legit SLD
            "github.com.",
        ] {
            let s = score(domain).expect("2+ labels should always score");
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
            let s = score(domain).expect("2+ labels should always score");
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
        let s = score("hjfgqhwjeqmqevqk.co.uk.").unwrap();
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
        assert!(score("co.uk.").is_some());
    }

    #[test]
    fn cloudfront_subdomain_does_not_leak_into_scored_label() {
        // Regression guard for the specific false-positive class this
        // module is designed to avoid: a random-looking CDN subdomain must
        // not be what gets scored.
        let s = score("d1a2b3c4d5e6f7.cloudfront.net.").unwrap();
        assert_eq!(s.label, "cloudfront");
    }

    #[test]
    fn single_label_returns_none() {
        assert_eq!(score("localhost"), None);
        assert_eq!(score("localhost."), None);
    }

    #[test]
    fn root_query_returns_none() {
        assert_eq!(score("."), None);
        assert_eq!(score(""), None);
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
            let _ = score(input);
        }
    }

    #[test]
    fn purely_numeric_label_does_not_panic_on_vowel_ratio() {
        // vowel_ratio's empty-alpha branch: a label with digits only.
        let s = score("12345.com.").unwrap();
        assert!(s.score.is_finite());
    }

    #[test]
    fn score_is_always_clamped_to_one() {
        // Longest possible label hitting every heuristic at once must not
        // exceed the documented [0.0, 1.0] range.
        let s = score("bcdfghjklmnpqrstvwxyzbcdfghjklmnpqrstvwxyz1234567890.com.").unwrap();
        assert!((0.0..=1.0).contains(&s.score));
    }
}
