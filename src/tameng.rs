//! TAMENG DGA-event forwarding.
//!
//! Sends a `DnsEvent` POST to a live, already-deployed TAMENG/"Tameng"
//! receiver (github.com/koodoxz/tameng)
//! when RUNUT's DGA heuristic (see dga.rs) flags a query. This module only
//! builds the request shape and small stateless helpers (URL construction,
//! failure-log rate limiting, wire-label domain escaping) -- the actual
//! non-blocking dispatch (spawn, client reuse, and the ClientIP-availability
//! decision) lives in
//! server/mod.rs next to the DGA alert block it fires from, since that is
//! where tameng.enabled and the per-connection client address are both
//! already in scope.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Exact wire shape expected by the TAMENG receiver's `DNSEvent` struct
/// (github.com/koodoxz/tameng). Field
/// names/casing must match its `json:"..."` tags precisely -- `client_ip`
/// and `domain` are REQUIRED server-side (400 if empty); the rest are
/// optional there (`omitempty`).
///
/// `api_key` is intentionally NOT part of this struct: it is sent as a
/// header (`Authorization: Bearer ...`), not a body field -- see
/// `server/mod.rs`'s `maybe_send_tameng_dga_event`. Authentication on the
/// receiver today is IP-allowlist only; the header is forward-compatible
/// but not yet enforced server-side (documented there, not here, since
/// this module has no knowledge of transport/headers).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DnsEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub client_ip: String,
    pub domain: String,
    pub score: f64,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Builds the full `/api/v1/dns-events` URL from `tameng.url`, handling
/// both a trailing-slash and no-trailing-slash base URL so the result is
/// never malformed.
pub fn build_dns_events_url(base_url: &str) -> String {
    format!("{}/api/v1/dns-events", base_url.trim_end_matches('/'))
}

/// Builds the outbound `domain` string for a TAMENG DGA event from raw
/// wire-format DNS label bytes (most-specific label first), WITHOUT calling
/// `Name::to_string()` (the exact vulnerability this feature's DGA scoring
/// already avoids -- see `dga.rs`'s module doc comment) and WITHOUT
/// `String::from_utf8_lossy` (which `dga.rs::score()`'s own doc comment
/// explicitly rejects for score-manufacturing reasons, applied here to
/// every label in the domain, not just the registrable one dga.rs scores).
///
/// Two properties distinguish this from a naive `labels.join(".")`:
///
/// 1. **Non-UTF-8 labels skip the whole event, they are never
///    lossy-decoded.** If ANY label's raw bytes are not valid UTF-8, this
///    returns `None` ("do not send this event") -- mirroring how
///    `dga.rs::score()` already treats a non-UTF-8 *registrable* label,
///    extended here to every label since this function (unlike `score`)
///    must render the whole domain, not just one label.
/// 2. **Literal `.` (and `\`) bytes inside a single wire label are
///    escaped before joining.** RFC 1035 labels are length-prefixed on the
///    wire, not dot-delimited, so a literal `.` byte legally inside one
///    label would otherwise be indistinguishable from a real label-boundary
///    dot once joined -- exactly the desync `dga.rs` has a dedicated
///    regression test for
///    (`raw_label_with_literal_dot_byte_does_not_desync_like_display_string_would`).
///    Each label's own literal `\` bytes are doubled first (`\` -> `\\`),
///    then literal `.` bytes are escaped (`.` -> `\.`), so a dot that came
///    from label content can never be misread as a boundary a human or
///    downstream consumer might re-split on. This mirrors the escaping
///    `Name`'s own non-IDNA `Display` path uses for the same byte, but is
///    implemented directly on the raw label bytes here rather than by
///    calling `Name::to_string()` -- reusing that method is the original
///    vulnerability this whole rewrite exists to avoid.
/// 3. **ASCII control/non-printable bytes are hex-escaped
///    (`\xHH`, lowercase hex, always 2 digits).** A wire label can legally
///    contain any byte, including raw control characters (`\n`, `\r`,
///    ANSI/terminal escape sequences, `0x7f` DEL, etc.) -- these would
///    otherwise pass straight through into the `domain` field sent to the
///    external TAMENG receiver, which is exactly the log/data-forgery
///    class this codebase already guards against at the local `warn!` call
///    site in `server/mod.rs` (Debug-escaped there for the same reason,
///    per that call site's own comment). This escaping only ever fires for
///    genuinely control/non-printable ASCII (byte < `0x20`, or `0x7f`) --
///    it does NOT touch bytes `>= 0x80`, since `label` was already
///    validated as UTF-8 above and those bytes are legitimate continuation
///    bytes of real multi-byte UTF-8 characters (mangling them byte-by-byte
///    would corrupt valid non-ASCII content for no security benefit).
///    Applied LAST, after the backslash/dot escaping above: a control byte
///    can never itself be `\` or `.`, so the three escape passes cannot
///    interact, and because backslash-doubling already ran first, any
///    single (non-doubled) `\x` in the output is unambiguously one of
///    these synthetic escapes, never literal label content -- the same
///    unambiguity guarantee the `\.`/`\\` escaping above provides.
///
/// Returns `None` for zero labels (nothing to send), matching `dga.rs`'s
/// own "not scoreable" convention rather than sending an empty string.
///
/// Deliberately named for what it actually guarantees (UTF-8-validated,
/// escaped-for-ambiguity) rather than "canonical" -- it does not lowercase,
/// IDNA-normalize, or otherwise canonicalize the domain; it only makes the
/// join safe against the three vulnerabilities above.
pub fn build_alert_domain(labels: &[&[u8]]) -> Option<String> {
    if labels.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::with_capacity(labels.len());
    for label in labels {
        let s = std::str::from_utf8(label).ok()?;
        // Escape existing backslashes FIRST, then escape dots -- if this
        // were reversed, a dot we just escaped (introducing a new `\`)
        // would be caught by a subsequent backslash-escaping pass and
        // double-escaped, corrupting the output.
        let dot_and_backslash_escaped = s.replace('\\', "\\\\").replace('.', "\\.");
        // Hex-escape ASCII control/non-printable bytes LAST (see point 3
        // in the doc comment above for why the ordering and the `>= 0x80`
        // exclusion are both load-bearing). Iterating `.chars()` rather
        // than raw bytes keeps multi-byte UTF-8 sequences intact --
        // `is_ascii_control()` is false for every non-ASCII `char`, so
        // this pass is a no-op on them.
        let mut fully_escaped = String::with_capacity(dot_and_backslash_escaped.len());
        for c in dot_and_backslash_escaped.chars() {
            if c.is_ascii_control() {
                fully_escaped.push_str(&format!("\\x{:02x}", c as u32));
            } else {
                fully_escaped.push(c);
            }
        }
        parts.push(fully_escaped);
    }
    Some(parts.join("."))
}

/// Minimum interval between logged TAMENG POST-failure warnings. The
/// per-domain LRU dedup (`DnsServer::dga_alert_seen`) already prevents
/// re-alerting on the *same* label, but a sustained TAMENG outage
/// combined with traffic cycling through many *distinct* DGA-scoring
/// domains could otherwise still log one `warn!` per distinct domain -- a
/// second, narrower log-flood vector. This gate caps how often the
/// failure itself is logged, independent of which domain triggered it.
const FAILURE_LOG_INTERVAL_MS: u64 = 30_000;

/// Returns true if a TAMENG POST-failure warning should be logged right
/// now, atomically claiming the slot so concurrent callers don't all log
/// at once. Never panics: a system-clock error before the UNIX epoch
/// fails open (logs) rather than panicking or silently suppressing all
/// future failure logs forever.
pub fn should_log_tameng_failure(gate: &AtomicU64) -> bool {
    let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(_) => {
            // A clock set before the UNIX epoch is a broken-environment edge
            // case, not something an attacker can trigger from the network --
            // fail open (log this one call) rather than panic. Critically,
            // do NOT write a poisoned value (e.g. u64::MAX) into `gate`
            // here: every future `now_ms.saturating_sub(gate)` would then
            // evaluate to 0, permanently suppressing all future failure
            // logs forever, not just this one -- found in review. Return
            // early and leave the gate untouched so a later real timestamp
            // still compares correctly.
            return true;
        }
    };
    let last = gate.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < FAILURE_LOG_INTERVAL_MS {
        return false;
    }
    // compare_exchange so concurrent callers racing past the check above
    // don't all win and all log -- only the one that successfully claims
    // the slot proceeds.
    gate.compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_builds_correctly_without_trailing_slash() {
        assert_eq!(
            build_dns_events_url("https://tameng.example.com"),
            "https://tameng.example.com/api/v1/dns-events"
        );
    }

    #[test]
    fn url_builds_correctly_with_trailing_slash() {
        assert_eq!(
            build_dns_events_url("https://tameng.example.com/"),
            "https://tameng.example.com/api/v1/dns-events"
        );
    }

    #[test]
    fn url_handles_multiple_trailing_slashes() {
        // trim_end_matches('/') strips ALL trailing slashes, not just one --
        // document and lock in this behavior rather than leaving it
        // implicit.
        assert_eq!(
            build_dns_events_url("https://host//"),
            "https://host/api/v1/dns-events"
        );
    }

    #[test]
    fn dns_event_json_shape_matches_go_receiver_contract() {
        let event = DnsEvent {
            event_type: "dga".to_string(),
            client_ip: "203.0.113.7".to_string(),
            domain: "xkjqwzpqmnbvcxzl.com".to_string(),
            score: 0.85,
            reason: "high_entropy,long_consonant_run".to_string(),
            actor_id: None,
            timestamp: None,
            source: Some("runut".to_string()),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "dga");
        assert_eq!(json["client_ip"], "203.0.113.7");
        assert_eq!(json["domain"], "xkjqwzpqmnbvcxzl.com");
        assert_eq!(json["score"], 0.85);
        assert_eq!(json["reason"], "high_entropy,long_consonant_run");
        assert_eq!(json["source"], "runut");
        // Optional None fields must be omitted, not emitted as null --
        // matches Go's `omitempty` on ActorID/Timestamp.
        assert!(json.get("actor_id").is_none());
        assert!(json.get("timestamp").is_none());
    }

    #[test]
    fn dns_event_emits_actor_id_and_timestamp_when_present() {
        let event = DnsEvent {
            event_type: "dga".to_string(),
            client_ip: "10.0.0.1".to_string(),
            domain: "example.com".to_string(),
            score: 0.5,
            reason: "high_entropy".to_string(),
            actor_id: Some("actor-123".to_string()),
            timestamp: Some("2026-08-06T00:00:00Z".to_string()),
            source: Some("runut".to_string()),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["actor_id"], "actor-123");
        assert_eq!(json["timestamp"], "2026-08-06T00:00:00Z");
    }

    #[test]
    fn failure_log_gate_allows_first_call_and_suppresses_immediate_repeat() {
        let gate = AtomicU64::new(0);
        assert!(
            should_log_tameng_failure(&gate),
            "first call should log (gate starts at epoch 0, far in the past)"
        );
        assert!(
            !should_log_tameng_failure(&gate),
            "immediate repeat within the interval must be suppressed"
        );
    }

    #[test]
    fn failure_log_gate_allows_logging_again_after_interval_elapsed() {
        let gate = AtomicU64::new(0);
        assert!(should_log_tameng_failure(&gate));
        // Manually rewind the gate to simulate the interval having elapsed,
        // rather than sleeping in a unit test.
        gate.store(0, Ordering::Relaxed);
        assert!(
            should_log_tameng_failure(&gate),
            "resetting the gate to epoch 0 must allow logging again"
        );
    }

    #[test]
    fn build_alert_domain_joins_plain_ascii_labels_with_dots() {
        let labels: [&[u8]; 3] = [b"www", b"example", b"com"];
        assert_eq!(
            build_alert_domain(&labels),
            Some("www.example.com".to_string())
        );
    }

    #[test]
    fn build_alert_domain_returns_none_for_zero_labels() {
        assert_eq!(build_alert_domain(&[]), None);
    }

    #[test]
    fn build_alert_domain_returns_none_when_any_label_is_not_valid_utf8() {
        let invalid: &[u8] = &[0xC3, 0x28]; // malformed 2-byte UTF-8 sequence
        // Non-UTF-8 in a NON-registrable (leading) label must also skip the
        // whole event -- dga.rs's own None-on-non-UTF8 contract only
        // covers the single registrable label; this helper renders every
        // label, so it must apply the same "skip, never lossy-decode" rule
        // to all of them, not just one.
        let labels: [&[u8]; 3] = [invalid, b"example", b"com"];
        assert_eq!(build_alert_domain(&labels), None);
    }

    #[test]
    fn build_alert_domain_never_uses_lossy_decoding_for_non_registrable_labels() {
        // Regression guard for the round-3 bug: a prior version used
        // `String::from_utf8_lossy` per label, which `dga.rs::score()`'s own
        // doc comment explicitly rejects (replaces invalid bytes with a
        // fixed placeholder under attacker control of how many/where --
        // the same score-manufacturing class this rewrite exists to close).
        // If this function ever regresses to lossy decoding, this call
        // would return `Some("\u{FFFD}.com".to_string())` instead of
        // `None`.
        let invalid: &[u8] = &[0xFF, 0xFE];
        let labels: [&[u8]; 2] = [invalid, b"com"];
        assert_eq!(build_alert_domain(&labels), None);
    }

    #[test]
    fn build_alert_domain_escapes_literal_dot_byte_inside_a_single_label() {
        // RFC 1035 labels are length-prefixed on the wire, not
        // dot-delimited -- a literal '.' byte legally inside ONE label
        // must not be joinable in a way that is indistinguishable from a
        // real label-boundary dot. Mirrors dga.rs's own regression test
        // for the same underlying desync
        // (`raw_label_with_literal_dot_byte_does_not_desync_like_display_string_would`).
        let evil_label: &[u8] = b"xqzjkvwb.nmpqr";
        let labels: [&[u8]; 2] = [evil_label, b"com"];
        let domain = build_alert_domain(&labels).unwrap();

        let escaped_dots = domain.matches("\\.").count();
        let total_dots = domain.matches('.').count();
        assert_eq!(
            escaped_dots, 1,
            "the literal dot inside the label must be escaped, got {domain:?}"
        );
        assert_eq!(
            total_dots - escaped_dots,
            1,
            "exactly one real (unescaped) label-boundary separator must \
             remain, got {domain:?}"
        );
    }

    #[test]
    fn build_alert_domain_escapes_literal_backslash_before_escaping_dots() {
        // Wire label containing a literal backslash followed by a literal
        // dot, both as part of ONE label's content (not two labels).
        let label: &[u8] = &[b'a', b'\\', b'b', b'.', b'c'];
        let labels: [&[u8]; 2] = [label, b"com"];
        let domain = build_alert_domain(&labels).unwrap();

        // Verified by counting escaped vs. unescaped occurrences rather
        // than a hand-transcribed expected literal, to avoid a
        // transcription bug in the test itself.
        let escaped_dots = domain.matches("\\.").count();
        let total_dots = domain.matches('.').count();
        assert_eq!(escaped_dots, 1, "the literal dot must be escaped, got {domain:?}");
        assert_eq!(
            total_dots - escaped_dots,
            1,
            "exactly one real separator must remain, got {domain:?}"
        );
        assert!(
            domain.contains("\\\\"),
            "a literal backslash in label content must be doubled, got {domain:?}"
        );
    }

    #[test]
    fn build_alert_domain_escapes_control_characters() {
        // Round-3 finding (NEW-4): a raw newline byte inside a label must
        // never reach the outbound `domain` field unescaped -- the same
        // log/data-forgery class the local `warn!` call site already
        // guards against via Debug-escaping.
        let evil_label: &[u8] = b"abc\ndef";
        let labels: [&[u8]; 2] = [evil_label, b"com"];
        let domain = build_alert_domain(&labels).unwrap();

        assert!(
            !domain.contains('\n'),
            "a raw newline must not appear unescaped, got {domain:?}"
        );
        assert!(
            domain.contains("\\x0a"),
            "the newline must be hex-escaped as \\x0a, got {domain:?}"
        );
    }

    #[test]
    fn build_alert_domain_escapes_arbitrary_control_byte_and_del() {
        // 0x01 (SOH) and 0x7f (DEL) are both non-printable ASCII outside
        // the `.`/`\` special cases already covered by other tests.
        let label: &[u8] = &[0x01, b'x', 0x7f, b'y'];
        let labels: [&[u8]; 2] = [label, b"com"];
        let domain = build_alert_domain(&labels).unwrap();

        assert!(
            domain.contains("\\x01"),
            "SOH (0x01) must be hex-escaped, got {domain:?}"
        );
        assert!(
            domain.contains("\\x7f"),
            "DEL (0x7f) must be hex-escaped, got {domain:?}"
        );
    }

    #[test]
    fn build_alert_domain_leaves_valid_multibyte_utf8_untouched() {
        // Bytes >= 0x80 are legitimate continuation bytes of real UTF-8
        // characters once `label` has passed UTF-8 validation -- the
        // control-byte escaping pass must not mangle them.
        let label: &[u8] = "café".as_bytes();
        let labels: [&[u8]; 2] = [label, b"com"];
        let domain = build_alert_domain(&labels).unwrap();

        assert!(
            domain.starts_with("café."),
            "valid multi-byte UTF-8 content must pass through unescaped, got {domain:?}"
        );
    }
}
