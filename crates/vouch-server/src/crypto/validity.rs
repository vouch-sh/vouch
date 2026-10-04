// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The window of time in which a token or a timestamped event is accepted,
//! and the RFC 7519 `NumericDate` the window's bounds are read from.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A JWT time claim (`exp`, `nbf`, `iat`) as another party serialized it.
///
/// RFC 7519 §2: a NumericDate is "A JSON numeric value representing the
/// number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
/// date/time, ignoring leap seconds", and the same definition says
/// "non-integer values can be represented". Every time claim read from a JWT
/// that another party minted (an upstream IdP's ID token, a DPoP proof, a
/// Request Object, a client assertion) has this type, so a producer that
/// writes `1700000000.5` is judged by the window check rather than refused
/// by the parser. Tokens this server mints carry whole seconds and keep
/// `i64` fields.
///
/// Windows are judged at whole-second resolution (`ArrivalTime::as_second`),
/// and a fractional value is carried as the next whole second. For an
/// integer `now`, `now < exp` holds exactly when `now < ceil(exp)`, and
/// `now >= nbf` exactly when `now >= ceil(nbf)`, so the RFC 7519 §4.1.4 and
/// §4.1.5 comparisons are unchanged by the rounding. A value that is not a
/// JSON number, is not finite, or lies outside ±2^53 seconds (where an `f64`
/// stops being exact) fails to deserialize, which fails the token closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NumericDate(i64);

impl NumericDate {
    /// Largest magnitude an `f64` represents exactly as an integer (2^53).
    const EXACT_F64_MAGNITUDE: f64 = 9_007_199_254_740_992.0;

    /// A fractional NumericDate rounds up to the whole second that judges
    /// `exp` and `nbf` identically for an integer `now`; see the type doc.
    fn from_f64(value: f64) -> Option<Self> {
        let whole = value.ceil();
        if !whole.is_finite() || whole.abs() > Self::EXACT_F64_MAGNITUDE {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`whole` is integral and within ±2^53, so the cast is exact"
        )]
        Some(Self(whole as i64))
    }
}

impl From<i64> for NumericDate {
    fn from(seconds: i64) -> Self {
        Self(seconds)
    }
}

impl From<NumericDate> for i64 {
    fn from(date: NumericDate) -> Self {
        date.0
    }
}

impl Serialize for NumericDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for NumericDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NumericDateVisitor;

        impl Visitor<'_> for NumericDateVisitor {
            type Value = NumericDate;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 7519 NumericDate (a JSON number of seconds)")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<NumericDate, E> {
                Ok(NumericDate(value))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<NumericDate, E> {
                i64::try_from(value)
                    .map(NumericDate)
                    .map_err(|_| E::custom("NumericDate is beyond the representable range"))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<NumericDate, E> {
                NumericDate::from_f64(value)
                    .ok_or_else(|| E::custom("NumericDate is not a finite number of seconds"))
            }
        }

        deserializer.deserialize_any(NumericDateVisitor)
    }
}

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
    /// but is not a [`NumericDate`]. RFC 7519 §4.1.4 and §4.1.5: each value
    /// "MUST be a number containing a NumericDate value."
    pub(crate) fn from_token(token: &str) -> Option<Self> {
        let payload = super::jwt::decode_segment(token.split('.').nth(1)?)?;
        Self::from_payload(&serde_json::from_slice(&payload).ok()?)
    }

    /// Read the window from a decoded JWT payload; see [`Self::from_token`].
    pub(crate) fn from_payload(payload: &serde_json::Value) -> Option<Self> {
        let read = |name| match payload.get(name) {
            Some(value) => NumericDate::deserialize(value)
                .ok()
                .map(|d| Some(i64::from(d))),
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

#[cfg(test)]
mod tests {
    use super::{NumericDate, ValidityWindow};

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
        // RFC 7519 §2: "non-integer values can be represented."
        assert!(
            read(serde_json::json!({"exp": 10.5, "nbf": 5.0}))
                .is_some_and(|w| w.expires == Some(11) && w.not_before == Some(5)),
            "a fractional NumericDate is read, not refused"
        );
    }

    // RFC 7519 §2: a NumericDate is "A JSON numeric value representing the
    // number of seconds from 1970-01-01T00:00:00Z UTC", and "non-integer
    // values can be represented."
    #[test]
    fn numeric_date_reads_every_json_number() {
        let read = |v: serde_json::Value| serde_json::from_value::<NumericDate>(v).ok();
        assert_eq!(read(serde_json::json!(NOW)), Some(NumericDate(NOW)));
        assert_eq!(
            read(serde_json::json!(1_700_000_000.0_f64)),
            Some(NumericDate(NOW)),
            "a whole-valued float is the same instant as the integer"
        );
        assert_eq!(
            read(serde_json::json!(1_700_000_000.5_f64)),
            Some(NumericDate(NOW + 1)),
            "a fraction rounds up to the whole second that judges exp and nbf alike"
        );
        assert_eq!(
            read(serde_json::json!(-0.5_f64)),
            Some(NumericDate(0)),
            "ceil, not truncation, on either side of the epoch"
        );
        assert_eq!(read(serde_json::json!(u64::MAX)), None, "beyond i64");
        assert_eq!(
            read(serde_json::json!(1.0e16_f64)),
            None,
            "beyond the range an f64 represents exactly"
        );
        assert_eq!(
            read(serde_json::json!("1700000000")),
            None,
            "a string is not a number"
        );
        assert_eq!(read(serde_json::json!(null)), None);
    }

    // For an integer `now`, `now < exp` iff `now < ceil(exp)` and
    // `now >= nbf` iff `now >= ceil(nbf)`: the rounding leaves the RFC 7519
    // §4.1.4 and §4.1.5 comparisons exactly as written.
    #[test]
    fn fractional_bounds_judge_like_the_real_number() {
        let payload = serde_json::json!({
            "exp": 1_700_000_000.5_f64,
            "nbf": 1_699_999_990.5_f64,
        });
        let accepts =
            |now| ValidityWindow::from_payload(&payload).is_some_and(|w| w.accepts_at(now, 0, 0));
        assert!(accepts(NOW), "now < exp (1700000000 < 1700000000.5)");
        assert!(!accepts(NOW + 1), "now > exp");
        assert!(accepts(NOW - 9), "now > nbf (1699999991 > 1699999990.5)");
        assert!(!accepts(NOW - 10), "now < nbf (1699999990 < 1699999990.5)");
    }

    #[test]
    fn numeric_date_serializes_as_whole_seconds() {
        assert_eq!(
            serde_json::to_string(&NumericDate(NOW)).ok().as_deref(),
            Some("1700000000")
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
