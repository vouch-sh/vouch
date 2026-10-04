// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The window of time in which a token or a timestamped event is accepted.

/// A validity window: accepted from `not_before` until just before `expires`,
/// judged against a caller-supplied `now` (Unix seconds) rather than a clock
/// read here.
///
/// Every time window the server enforces goes through this type, so the
/// boundaries are written once: JWT `exp` and `nbf` claims (access, state, and
/// upstream ID tokens, Request Objects, client assertions) and windows that
/// open at an issued-at instant and last a maximum age (DPoP proof `iat`,
/// step-up `auth_time`).
///
/// Each caller supplies its own clock-skew leeway, which RFC 7519 §4.1.4 and
/// §4.1.5 both permit: "Implementers MAY provide for some small leeway,
/// usually no more than a few minutes, to account for clock skew."
#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidityWindow {
    not_before: Option<i64>,
    expires: Option<i64>,
}

impl ValidityWindow {
    /// `nbf` leeway for tokens this server issued: one instance can mint a
    /// token that another validates within the same second. The same
    /// tolerance DPoP proofs get for client clocks. Vouch's own `exp` gets
    /// none.
    pub(crate) const OWN_TOKEN_NBF_LEEWAY_SECS: i64 = 60;

    /// The window a JWT's `exp` and `nbf` claims describe.
    pub(crate) fn from_claims(exp: Option<i64>, nbf: Option<i64>) -> Self {
        Self {
            not_before: nbf,
            expires: exp,
        }
    }

    /// A window that opens at `issued_at` and lasts `max_age` seconds.
    pub(crate) fn issued_at(issued_at: i64, max_age: i64) -> Self {
        Self {
            not_before: Some(issued_at),
            expires: Some(issued_at.saturating_add(max_age)),
        }
    }

    /// Read the window from a compact JWS whose signature has already been
    /// verified.
    ///
    /// `None` when the payload does not decode, or `exp` or `nbf` is present
    /// but not a NumericDate. RFC 7519 §4.1.4 and §4.1.5: each value "MUST be
    /// a number containing a NumericDate value", and §2 defines NumericDate
    /// as "a JSON numeric value" whose fractional seconds "MAY be
    /// represented by a decimal fraction" — so a float is accepted.
    pub(crate) fn from_token(token: &str) -> Option<Self> {
        let payload = super::jwt::decode_segment(token.split('.').nth(1)?)?;
        Self::from_payload(&serde_json::from_slice(&payload).ok()?)
    }

    /// Read the window from a decoded JWT payload; see [`Self::from_token`].
    pub(crate) fn from_payload(payload: &serde_json::Value) -> Option<Self> {
        let read = |name| match payload.get(name) {
            Some(value) => numeric_date(value).map(Some),
            None => Some(None),
        };
        Some(Self::from_claims(read("exp")?, read("nbf")?))
    }

    /// RFC 7519 §4.1.4: "the current date/time MUST be before the expiration
    /// date/time listed in the "exp" claim", so the window has closed once
    /// `now - leeway` reaches `expires`. A window without an end never closes
    /// here; callers for which `exp` is required check for it separately.
    pub(crate) fn expired_at(&self, now: i64, leeway: i64) -> bool {
        self.expires
            .is_some_and(|expires| now.saturating_sub(leeway) >= expires)
    }

    /// RFC 7519 §4.1.5: "the current date/time MUST be after or equal to the
    /// not-before date/time listed in the "nbf" claim", so the window has not
    /// opened while `now + leeway` is before `not_before`.
    pub(crate) fn not_yet_valid_at(&self, now: i64, leeway: i64) -> bool {
        self.not_before
            .is_some_and(|not_before| now.saturating_add(leeway) < not_before)
    }

    /// Whether `now` falls inside the window, with `exp_leeway` past its end
    /// and `nbf_leeway` before its start.
    pub(crate) fn accepts_at(&self, now: i64, exp_leeway: i64, nbf_leeway: i64) -> bool {
        !self.expired_at(now, exp_leeway) && !self.not_yet_valid_at(now, nbf_leeway)
    }

    /// Whether a token this server issued may be accepted at `now`: `exp` is
    /// required and gets no leeway, `nbf` gets
    /// [`Self::OWN_TOKEN_NBF_LEEWAY_SECS`].
    pub(crate) fn accepts_own_token_at(&self, now: i64) -> bool {
        self.expires.is_some() && self.accepts_at(now, 0, Self::OWN_TOKEN_NBF_LEEWAY_SECS)
    }
}

/// Read a JWT `exp`/`nbf` (or any RFC 7519 time) claim as a NumericDate.
///
/// RFC 7519 §2: `NumericDate` is "a JSON numeric value" whose fractional
/// seconds "MAY be represented by a decimal fraction", so an OP may
/// serialize `exp`/`nbf` as a JSON float (e.g. `1700000000.0` or
/// `1700000000.5`). `serde_json::Value::as_i64()` returns `None` for every
/// float — even a whole-valued one — so reading the claim through `as_i64`
/// alone rejects RFC-7519-conformant tokens. Read it as a JSON number,
/// taking an integer directly and rounding a float to whole seconds the way
/// `jsonwebtoken`'s own `visit_f64` deserializer does
/// (`value.round() as u64`). Returns `None` for any non-number value, since
/// RFC 7519 §4.1.4 and §4.1.5 each require "a number containing a
/// NumericDate value".
fn numeric_date(value: &serde_json::Value) -> Option<i64> {
    let n = value.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i);
    }
    let f = n.as_f64()?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "NumericDate is seconds since epoch; a finite f64 that \
                  `round()`ed into i64 matches `jsonwebtoken`'s `visit_f64` \
                  (`value.round() as u64`). Out-of-range saturation and NaN→0 \
                  are non-conformant inputs that fail closed at the window check"
    )]
    Some(f.round() as i64)
}

#[cfg(test)]
mod tests {
    use super::ValidityWindow;

    const NOW: i64 = 1_700_000_000;

    // RFC 7519 §4.1.4: "the current date/time MUST be before the expiration
    // date/time listed in the "exp" claim." Covers the KMS state-token path,
    // whose live `VerifyMac` call cannot run in a unit test.
    #[test]
    fn exp_boundary() {
        let window = |exp| ValidityWindow::from_claims(Some(exp), None);
        assert!(
            window(NOW + 1).accepts_own_token_at(NOW),
            "one second before exp"
        );
        assert!(!window(NOW).accepts_own_token_at(NOW), "at exp");
        assert!(!window(NOW - 29).expired_at(NOW, 30), "inside the leeway");
        assert!(window(NOW - 30).expired_at(NOW, 30), "at exp + leeway");
        assert!(
            !ValidityWindow::from_claims(None, None).accepts_own_token_at(NOW),
            "this server's tokens always carry exp"
        );
    }

    // RFC 7519 §4.1.5: "the current date/time MUST be after or equal to the
    // not-before date/time listed in the "nbf" claim".
    #[test]
    fn nbf_boundary() {
        let window = ValidityWindow::from_claims(None, Some(NOW));
        assert!(!window.not_yet_valid_at(NOW, 0), "now == nbf");
        assert!(window.not_yet_valid_at(NOW - 1, 0));
        assert!(!window.not_yet_valid_at(NOW - 60, 60), "inside the leeway");
        assert!(window.not_yet_valid_at(NOW - 61, 60));
    }

    #[test]
    fn from_payload() {
        let read = |payload| ValidityWindow::from_payload(&payload);
        assert!(read(serde_json::json!({"exp": 10})).is_some());
        assert!(read(serde_json::json!({"exp": 10, "nbf": 5})).is_some());
        assert!(read(serde_json::json!({})).is_some_and(|w| w.expires.is_none()));
        assert!(read(serde_json::json!({"exp": "10"})).is_none());
        assert!(
            read(serde_json::json!({"exp": 10, "nbf": "5"})).is_none(),
            "RFC 7519 §4.1.5: nbf \"MUST be a number containing a NumericDate value\""
        );
    }

    // RFC 7519 §2: NumericDate is "a JSON numeric value" whose fractional
    // seconds "MAY be represented by a decimal fraction", so a JSON float is
    // a conformant `exp`/`nbf` and must be accepted — even a whole-valued one
    // (`1700000000.0`), which `serde_json` stores as `N::Float` and which
    // `Value::as_i64()` rejects. Regression for the float-rejection bug
    // introduced by commit 41c39593: that reader used `as_i64()` alone, which
    // returns `None` for every JSON float and made `from_payload` reject
    // RFC-7519-conformant tokens.
    #[test]
    fn from_payload_accepts_float_numeric_date() {
        let read = |payload| ValidityWindow::from_payload(&payload);

        // Whole-valued float — the exact shape that `as_i64()` rejected.
        assert!(
            read(serde_json::json!({"exp": 1700000000.0_f64}))
                .is_some_and(|w| w.expires == Some(1700000000)),
            "whole-valued float exp must round to the same integer"
        );

        // Fractional float — rounds half away from zero, matching
        // `jsonwebtoken`'s `visit_f64` (`value.round() as u64`).
        assert!(
            read(serde_json::json!({"exp": 1700000000.5_f64, "nbf": 1699999999.5_f64}))
                .is_some_and(|w| w.expires == Some(1700000001) && w.not_before == Some(1700000000)),
            "fractional floats must round half away from zero"
        );

        // Down-rounding for a fractional part below 0.5.
        assert!(
            read(serde_json::json!({"exp": 1700000000.4_f64}))
                .is_some_and(|w| w.expires == Some(1700000000)),
            "1700000000.4 must round down"
        );

        // Float `nbf` alone (no `exp`).
        assert!(
            read(serde_json::json!({"nbf": 100.0_f64})).is_some_and(|w| w.not_before == Some(100)),
            "float nbf is a NumericDate"
        );

        // Integer values are unaffected by the float fallback.
        assert!(
            read(serde_json::json!({"exp": 10, "nbf": 5})).is_some_and(|w| w.accepts_at(7, 0, 0)),
            "integer claims parse and the window opens as before"
        );
    }

    #[test]
    fn issued_at_window_closes_at_max_age() {
        let window = ValidityWindow::issued_at(NOW - 60, 60);
        assert!(window.accepts_at(NOW - 1, 0, 0), "age max_age - 1");
        assert!(!window.accepts_at(NOW, 0, 0), "age max_age");
    }

    // A timestamp dated after `now` fails closed unless a skew is allowed.
    #[test]
    fn issued_at_window_future_timestamp() {
        assert!(!ValidityWindow::issued_at(NOW + 1, 60).accepts_at(NOW, 0, 0));
        assert!(ValidityWindow::issued_at(NOW + 60, 60).accepts_at(NOW, 0, 60));
        assert!(!ValidityWindow::issued_at(NOW + 61, 60).accepts_at(NOW, 0, 60));
    }

    #[test]
    fn saturating_arithmetic_does_not_overflow_at_bounds() {
        assert!(!ValidityWindow::issued_at(i64::MIN, 60).accepts_at(i64::MAX, 0, 0));
        assert!(!ValidityWindow::issued_at(i64::MAX, 60).accepts_at(i64::MIN, 0, 0));
    }
}
