// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The window of time in which a token or a timestamped event is accepted,
//! and the RFC 7519 `NumericDate` the window's bounds are read from.

use jiff::{SignedDuration, Timestamp};
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
/// Request Object, a client assertion) has this type, and the value is kept
/// as the instant it names: an integer through [`Timestamp::from_second`], a
/// fraction through [`SignedDuration::try_from_secs_f64`]. Both are checked
/// conversions, so a non-finite float or a value outside jiff's range fails
/// to deserialize and the token fails closed. A producer that writes
/// `1700000000.5` is then judged at that exact instant by [`ValidityWindow`].
///
/// Tokens this server mints carry whole seconds and keep `i64` claim fields;
/// [`ValidityWindow::from_payload`] reads them through this type as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NumericDate(Timestamp);

impl NumericDate {
    /// The instant this claim names.
    #[must_use]
    pub fn timestamp(self) -> Timestamp {
        self.0
    }
}

impl From<Timestamp> for NumericDate {
    fn from(at: Timestamp) -> Self {
        Self(at)
    }
}

impl Serialize for NumericDate {
    /// A whole second serializes as the JSON integer every consumer reads; a
    /// fraction serializes as the JSON number RFC 7519 §2 permits.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.subsec_nanosecond() == 0 {
            serializer.serialize_i64(self.0.as_second())
        } else {
            serializer.serialize_f64(self.0.duration_since(Timestamp::UNIX_EPOCH).as_secs_f64())
        }
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
                Timestamp::from_second(value)
                    .map(NumericDate)
                    .map_err(|e| E::custom(format!("NumericDate is not an instant: {e}")))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<NumericDate, E> {
                let seconds = i64::try_from(value)
                    .map_err(|_| E::custom("NumericDate is beyond the representable range"))?;
                self.visit_i64(seconds)
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<NumericDate, E> {
                SignedDuration::try_from_secs_f64(value)
                    .and_then(Timestamp::from_duration)
                    .map(NumericDate)
                    .map_err(|e| E::custom(format!("NumericDate is not an instant: {e}")))
            }
        }

        deserializer.deserialize_any(NumericDateVisitor)
    }
}

/// A validity window: accepted from `not_before` until just before `expires`,
/// judged against a caller-supplied `now` rather than a clock read here.
///
/// Every time window the server enforces goes through this type, so the
/// boundaries are written once: JWT `exp` and `nbf` claims (access, state, and
/// upstream ID tokens, Request Objects, client assertions) and windows that
/// open at an issued-at instant and last a maximum age (DPoP proof `iat`,
/// step-up `auth_time`).
///
/// Bounds and `now` are full-precision instants, so a fractional NumericDate
/// is compared exactly as RFC 7519 §4.1.4 and §4.1.5 state it. Decoders of
/// this server's own tokens receive `now` as whole seconds; because those
/// tokens carry whole-second claims, `floor(now) >= exp` holds exactly when
/// `now >= exp`, and the truncation changes no decision.
///
/// Each caller supplies its own clock-skew leeway, which RFC 7519 §4.1.4 and
/// §4.1.5 both permit: "Implementers MAY provide for some small leeway,
/// usually no more than a few minutes, to account for clock skew."
#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidityWindow {
    not_before: Option<Timestamp>,
    expires: Option<Timestamp>,
}

/// `at` moved by `secs`, clamped to the instants jiff represents: a window
/// bound that overflows is one that never opens or never closes.
fn shifted(at: Timestamp, secs: i64) -> Timestamp {
    at.checked_add(SignedDuration::from_secs(secs))
        .unwrap_or(if secs < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        })
}

impl ValidityWindow {
    /// `nbf` leeway for tokens this server issued: one instance can mint a
    /// token that another validates within the same second. The same
    /// tolerance DPoP proofs get for client clocks. Vouch's own `exp` gets
    /// none.
    pub(crate) const OWN_TOKEN_NBF_LEEWAY_SECS: i64 = 60;

    /// The window a JWT's `exp` and `nbf` claims describe.
    pub(crate) fn from_claims(exp: Option<NumericDate>, nbf: Option<NumericDate>) -> Self {
        Self {
            not_before: nbf.map(NumericDate::timestamp),
            expires: exp.map(NumericDate::timestamp),
        }
    }

    /// A window that opens at `issued_at` and lasts `max_age_secs` seconds.
    pub(crate) fn issued_at(issued_at: Timestamp, max_age_secs: i64) -> Self {
        Self {
            not_before: Some(issued_at),
            expires: Some(shifted(issued_at, max_age_secs)),
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
            Some(value) => NumericDate::deserialize(value).ok().map(Some),
            None => Some(None),
        };
        Some(Self::from_claims(read("exp")?, read("nbf")?))
    }

    /// RFC 7519 §4.1.4: "the current date/time MUST be before the expiration
    /// date/time listed in the "exp" claim", so the window has closed once
    /// `now - leeway` reaches `expires`. A window without an end never closes
    /// here; callers for which `exp` is required check for it separately.
    pub(crate) fn expired_at(&self, now: Timestamp, leeway_secs: i64) -> bool {
        self.expires
            .is_some_and(|expires| shifted(now, leeway_secs.saturating_neg()) >= expires)
    }

    /// RFC 7519 §4.1.5: "the current date/time MUST be after or equal to the
    /// not-before date/time listed in the "nbf" claim", so the window has not
    /// opened while `now + leeway` is before `not_before`.
    pub(crate) fn not_yet_valid_at(&self, now: Timestamp, leeway_secs: i64) -> bool {
        self.not_before
            .is_some_and(|not_before| shifted(now, leeway_secs) < not_before)
    }

    /// Whether `now` falls inside the window, with `exp_leeway_secs` past its
    /// end and `nbf_leeway_secs` before its start.
    pub(crate) fn accepts_at(
        &self,
        now: Timestamp,
        exp_leeway_secs: i64,
        nbf_leeway_secs: i64,
    ) -> bool {
        !self.expired_at(now, exp_leeway_secs) && !self.not_yet_valid_at(now, nbf_leeway_secs)
    }

    /// Whether a token this server issued may be accepted at `now`: `exp` is
    /// required and gets no leeway, `nbf` gets
    /// [`Self::OWN_TOKEN_NBF_LEEWAY_SECS`].
    pub(crate) fn accepts_own_token_at(&self, now: Timestamp) -> bool {
        self.expires.is_some() && self.accepts_at(now, 0, Self::OWN_TOKEN_NBF_LEEWAY_SECS)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test instants are literals inside jiff's range"
)]
mod tests {
    use super::{NumericDate, ValidityWindow};
    use jiff::{SignedDuration, Timestamp};

    const NOW: i64 = 1_700_000_000;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_second(secs).unwrap()
    }

    fn date(secs: i64) -> NumericDate {
        NumericDate::from(at(secs))
    }

    fn millis(ms: i64) -> SignedDuration {
        SignedDuration::from_millis(ms)
    }

    // RFC 7519 §4.1.4: "the current date/time MUST be before the expiration
    // date/time listed in the "exp" claim." Covers the KMS state-token path,
    // whose live `VerifyMac` call cannot run in a unit test.
    #[test]
    fn exp_boundary() {
        let window = |exp| ValidityWindow::from_claims(Some(date(exp)), None);
        assert!(
            window(NOW + 1).accepts_own_token_at(at(NOW)),
            "one second before exp"
        );
        assert!(!window(NOW).accepts_own_token_at(at(NOW)), "at exp");
        assert!(
            !window(NOW - 29).expired_at(at(NOW), 30),
            "inside the leeway"
        );
        assert!(window(NOW - 30).expired_at(at(NOW), 30), "at exp + leeway");
        assert!(
            !ValidityWindow::from_claims(None, None).accepts_own_token_at(at(NOW)),
            "this server's tokens always carry exp"
        );
    }

    // RFC 7519 §4.1.5: "the current date/time MUST be after or equal to the
    // not-before date/time listed in the "nbf" claim".
    #[test]
    fn nbf_boundary() {
        let window = ValidityWindow::from_claims(None, Some(date(NOW)));
        assert!(!window.not_yet_valid_at(at(NOW), 0), "now == nbf");
        assert!(window.not_yet_valid_at(at(NOW - 1), 0));
        assert!(
            !window.not_yet_valid_at(at(NOW - 60), 60),
            "inside the leeway"
        );
        assert!(window.not_yet_valid_at(at(NOW - 61), 60));
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
            read(serde_json::json!({"exp": 10.5, "nbf": 5.0})).is_some_and(|w| {
                w.expires == Some(at(10).checked_add(millis(500)).unwrap())
                    && w.not_before == Some(at(5))
            }),
            "a fractional NumericDate is read as the instant it names"
        );
    }

    // RFC 7519 §2: a NumericDate is "A JSON numeric value representing the
    // number of seconds from 1970-01-01T00:00:00Z UTC", and "non-integer
    // values can be represented."
    #[test]
    fn numeric_date_reads_every_json_number() {
        let read = |v: serde_json::Value| serde_json::from_value::<NumericDate>(v).ok();
        assert_eq!(read(serde_json::json!(NOW)), Some(date(NOW)));
        assert_eq!(
            read(serde_json::json!(1_700_000_000.0_f64)),
            Some(date(NOW)),
            "a whole-valued float is the same instant as the integer"
        );
        assert_eq!(
            read(serde_json::json!(1_700_000_000.5_f64)),
            Some(NumericDate::from(at(NOW).checked_add(millis(500)).unwrap())),
            "the fraction is kept"
        );
        assert_eq!(
            read(serde_json::json!(1_700_000_000.25_f64)),
            Some(NumericDate::from(at(NOW).checked_add(millis(250)).unwrap())),
            "no rounding to a coarser unit"
        );
        assert_eq!(
            read(serde_json::json!(-0.5_f64)),
            Some(NumericDate::from(
                Timestamp::UNIX_EPOCH.checked_sub(millis(500)).unwrap()
            )),
            "before the epoch is still an instant"
        );
        assert_eq!(read(serde_json::json!(u64::MAX)), None, "beyond i64");
        assert_eq!(
            read(serde_json::json!(1.0e16_f64)),
            None,
            "beyond the instants jiff represents"
        );
        assert_eq!(
            read(serde_json::json!("1700000000")),
            None,
            "a string is not a number"
        );
        assert_eq!(read(serde_json::json!(null)), None);
    }

    // RFC 7519 §4.1.4 ("MUST be before") and §4.1.5 ("after or equal to")
    // are judged at the fractional instant the claim names.
    #[test]
    fn fractional_bounds_are_judged_exactly() {
        let window = ValidityWindow::from_payload(&serde_json::json!({
            "exp": 1_700_000_000.5_f64,
            "nbf": 1_699_999_990.5_f64,
        }));
        let accepts = |now| window.is_some_and(|w| w.accepts_at(now, 0, 0));
        let exp = at(NOW).checked_add(millis(500)).unwrap();
        let nbf = at(NOW - 10).checked_add(millis(500)).unwrap();
        assert!(
            accepts(exp.checked_sub(millis(1)).unwrap()),
            "one millisecond before exp"
        );
        assert!(!accepts(exp), "at exp");
        assert!(accepts(nbf), "at nbf");
        assert!(
            !accepts(nbf.checked_sub(millis(1)).unwrap()),
            "one millisecond before nbf"
        );
    }

    #[test]
    fn numeric_date_serializes_as_the_number_it_was() {
        assert_eq!(
            serde_json::to_string(&date(NOW)).ok().as_deref(),
            Some("1700000000")
        );
        assert_eq!(
            serde_json::to_string(&NumericDate::from(
                at(NOW).checked_add(millis(500)).unwrap()
            ))
            .ok()
            .as_deref(),
            Some("1700000000.5")
        );
    }

    #[test]
    fn issued_at_window_closes_at_max_age() {
        let window = ValidityWindow::issued_at(at(NOW - 60), 60);
        assert!(window.accepts_at(at(NOW - 1), 0, 0), "age max_age - 1");
        assert!(!window.accepts_at(at(NOW), 0, 0), "age max_age");
    }

    // A timestamp dated after `now` fails closed unless a skew is allowed.
    #[test]
    fn issued_at_window_future_timestamp() {
        assert!(!ValidityWindow::issued_at(at(NOW + 1), 60).accepts_at(at(NOW), 0, 0));
        assert!(ValidityWindow::issued_at(at(NOW + 60), 60).accepts_at(at(NOW), 0, 60));
        assert!(!ValidityWindow::issued_at(at(NOW + 61), 60).accepts_at(at(NOW), 0, 60));
    }

    #[test]
    fn saturating_arithmetic_does_not_overflow_at_bounds() {
        assert!(!ValidityWindow::issued_at(Timestamp::MIN, 60).accepts_at(Timestamp::MAX, 0, 0));
        assert!(!ValidityWindow::issued_at(Timestamp::MAX, 60).accepts_at(Timestamp::MIN, 0, 0));
        assert!(
            !ValidityWindow::from_claims(Some(date(NOW)), None)
                .expired_at(Timestamp::MIN, i64::MAX)
        );
    }
}
