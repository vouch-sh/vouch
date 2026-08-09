// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OCSF (Open Cybersecurity Schema Framework) projection of audit events.
//!
//! Maps the ~40 [`AuditEventKind`] variants onto four OCSF IAM event
//! classes — Account Change (3001), Authentication (3002), Authorize
//! Session (3003), and Entity Management (3004) — for `GET
//! /api/v1/org/audit-events?format=ocsf`. Native JSON stays the canonical,
//! lossless representation; this is a projection for SIEM ingestion.
//!
//! Pure mapping, no I/O — [`to_ocsf`] takes a decoded [`AuditEvent`] and
//! returns an [`OcsfEvent`] ready to serialize. An unrecognized wire
//! `event_type` (future kind read by an older binary, or corrupted data)
//! never fails: it becomes a Base Event with the raw string preserved in
//! `unmapped`, per OCSF's own escape hatch for unclassified events.

use serde::{Serialize, Serializer};

use crate::db::audit::{AuditEvent, AuditEventKind};

/// OCSF schema version this mapping targets. Bump when adopting a newer
/// schema; the parity test below does not enforce a particular value, so
/// this is the only place the version needs to change.
const OCSF_SCHEMA_VERSION: &str = "1.9.0";

/// OCSF category for every class this mapper emits: Identity & Access
/// Management (`category_uid` 3).
const CATEGORY_UID_IAM: u16 = 3;
const CATEGORY_NAME_IAM: &str = "Identity & Access Management";
/// Category for the unmapped fallback (OCSF has no IAM-specific "unknown"
/// category; 0 is the schema-wide "Uncategorized" value).
const CATEGORY_UID_UNCATEGORIZED: u16 = 0;
const CATEGORY_NAME_UNCATEGORIZED: &str = "Uncategorized";

/// OCSF `class_uid` for the four IAM classes this mapper targets, plus the
/// `Base Event` fallback for wire strings that don't match a registered
/// [`AuditEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassUid {
    Base,
    AccountChange,
    Authentication,
    AuthorizeSession,
    EntityManagement,
}

impl ClassUid {
    const fn value(self) -> u16 {
        match self {
            Self::Base => 0,
            Self::AccountChange => 3001,
            Self::Authentication => 3002,
            Self::AuthorizeSession => 3003,
            Self::EntityManagement => 3004,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Base => "Base Event",
            Self::AccountChange => "Account Change",
            Self::Authentication => "Authentication",
            Self::AuthorizeSession => "Authorize Session",
            Self::EntityManagement => "Entity Management",
        }
    }
}

impl Serialize for ClassUid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.value())
    }
}

/// OCSF `status_id`. Universal across classes.
///
/// `pub(crate)` matches [`OcsfEvent`]'s own effective visibility — a `pub`
/// field on a `pub(crate)` struct can't point to a strictly module-private
/// type without a `private_interfaces` warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusId {
    Unknown,
    Success,
    Failure,
}

impl StatusId {
    const fn value(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Success => 1,
            Self::Failure => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Success => "Success",
            Self::Failure => "Failure",
        }
    }
}

impl Serialize for StatusId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.value())
    }
}

/// OCSF `severity_id`. Universal across classes; this mapper only ever
/// emits [`Self::Informational`] or [`Self::Medium`] — Vouch's audit log
/// has no higher-severity classification today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeverityId {
    Informational,
    Medium,
}

impl SeverityId {
    const fn value(self) -> u8 {
        match self {
            Self::Informational => 1,
            Self::Medium => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Informational => "Informational",
            Self::Medium => "Medium",
        }
    }
}

impl Serialize for SeverityId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.value())
    }
}

/// OCSF `activity_id` plus its human-readable name.
///
/// Not a single flat enum: OCSF assigns the *same* numeric ID to different
/// activities depending on the class (`Create` is `1` in both Account
/// Change and Entity Management, but `Enable` is `2` in Account Change and
/// `8` in Entity Management). Each constant below is scoped to the class
/// it's used with in [`ocsf_class`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActivityId {
    id: u8,
    name: &'static str,
}

impl ActivityId {
    const UNKNOWN: Self = Self {
        id: 0,
        name: "Unknown",
    };

    // Authentication (3002)
    const LOGON: Self = Self {
        id: 1,
        name: "Logon",
    };
    const LOGOFF: Self = Self {
        id: 2,
        name: "Logoff",
    };

    // Account Change (3001)
    const ACCOUNT_CREATE: Self = Self {
        id: 1,
        name: "Create",
    };
    const ACCOUNT_ENABLE: Self = Self {
        id: 2,
        name: "Enable",
    };
    const ACCOUNT_DISABLE: Self = Self {
        id: 5,
        name: "Disable",
    };
    const ACCOUNT_DELETE: Self = Self {
        id: 6,
        name: "Delete",
    };
    const MFA_FACTOR_ENABLE: Self = Self {
        id: 10,
        name: "MFA Factor Enable",
    };
    const MFA_FACTOR_DISABLE: Self = Self {
        id: 11,
        name: "MFA Factor Disable",
    };
    // OCSF `activity_id: 99` ("Other") is the catch-all for activities
    // without a predefined enum value. Per the OCSF 1.9.0 spec ("When
    // `activity_id` is `99` (Other), this attribute **must** contain the
    // source-specific activity label"), each of these carries a
    // source-specific `name` rather than the literal "Other", so SIEM
    // consumers can distinguish them at the classification layer without
    // parsing `data`. The original `event_type` is additionally preserved
    // in `unmapped` by [`to_ocsf`].
    const ADMIN_PROMOTE: Self = Self {
        id: 99,
        name: "Admin Promote",
    };
    const ADMIN_DEMOTE: Self = Self {
        id: 99,
        name: "Admin Demote",
    };
    const ADMIN_REVOKE_CREDENTIALS: Self = Self {
        id: 99,
        name: "Admin Revoke Credentials",
    };
    const IDENTITY_BOUND: Self = Self {
        id: 99,
        name: "Identity Bound",
    };

    // Authorize Session (3003)
    const ASSIGN_PRIVILEGES: Self = Self {
        id: 1,
        name: "Assign Privileges",
    };
    const OAUTH_TOKEN_REVOKED: Self = Self {
        id: 99,
        name: "OAuth Token Revoked",
    };

    // Entity Management (3004)
    const ENTITY_CREATE: Self = Self {
        id: 1,
        name: "Create",
    };
    const ENTITY_UPDATE: Self = Self {
        id: 3,
        name: "Update",
    };
    const ENTITY_DELETE: Self = Self {
        id: 4,
        name: "Delete",
    };
    const SCIM_OPERATION: Self = Self {
        id: 99,
        name: "SCIM Operation",
    };
}

impl Serialize for ActivityId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.id)
    }
}

/// The OCSF class/activity/status/severity a given [`AuditEventKind`]
/// maps onto.
struct OcsfMapping {
    class: ClassUid,
    activity: ActivityId,
    status: StatusId,
    severity: SeverityId,
}

impl OcsfMapping {
    const fn new(class: ClassUid, activity: ActivityId) -> Self {
        Self {
            class,
            activity,
            status: StatusId::Success,
            severity: SeverityId::Informational,
        }
    }

    const fn failure(mut self) -> Self {
        self.status = StatusId::Failure;
        self
    }

    const fn medium(mut self) -> Self {
        self.severity = SeverityId::Medium;
        self
    }
}

/// Map every registered [`AuditEventKind`] to its OCSF class and activity.
///
/// Exhaustive on `AuditEventKind` (no wildcard arm) so adding a new kind
/// without extending this match is a compile error, not a silent gap.
fn ocsf_class(kind: AuditEventKind) -> OcsfMapping {
    match kind {
        // Authentication (3002)
        AuditEventKind::LoginSuccess => {
            OcsfMapping::new(ClassUid::Authentication, ActivityId::LOGON)
        }
        AuditEventKind::LoginFailed => {
            OcsfMapping::new(ClassUid::Authentication, ActivityId::LOGON)
                .failure()
                .medium()
        }
        AuditEventKind::Logout => OcsfMapping::new(ClassUid::Authentication, ActivityId::LOGOFF),
        // A posture/temporal policy denial blocks credential issuance.
        AuditEventKind::PolicyDenied => {
            OcsfMapping::new(ClassUid::Authentication, ActivityId::LOGON)
                .failure()
                .medium()
        }
        AuditEventKind::DeviceAuthApproved => {
            OcsfMapping::new(ClassUid::Authentication, ActivityId::LOGON)
        }
        // A refused identity link is a blocked logon attempt: the asserted
        // upstream subject did not match the subject bound to the account.
        AuditEventKind::IdentityBindRefused => {
            OcsfMapping::new(ClassUid::Authentication, ActivityId::LOGON)
                .failure()
                .medium()
        }

        // Account Change (3001) — user account and credential lifecycle
        AuditEventKind::Enrollment => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::ACCOUNT_CREATE)
        }
        AuditEventKind::KeyRegistered => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::MFA_FACTOR_ENABLE)
        }
        AuditEventKind::KeyRemoved => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::MFA_FACTOR_DISABLE)
        }
        AuditEventKind::KeyRegistrationReplay => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::MFA_FACTOR_ENABLE)
                .failure()
                .medium()
        }
        // Binding an upstream (issuer, subject) identity mutates the account.
        AuditEventKind::IdentityBound => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::IDENTITY_BOUND)
        }
        AuditEventKind::AdminPromote => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::ADMIN_PROMOTE)
        }
        AuditEventKind::AdminDemote => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::ADMIN_DEMOTE)
        }
        AuditEventKind::AdminActivate => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::ACCOUNT_ENABLE)
        }
        AuditEventKind::AdminDeactivate => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::ACCOUNT_DISABLE)
        }
        AuditEventKind::AdminRevokeCredentials => OcsfMapping::new(
            ClassUid::AccountChange,
            ActivityId::ADMIN_REVOKE_CREDENTIALS,
        )
        .medium(),
        AuditEventKind::AdminRemoveUser => {
            OcsfMapping::new(ClassUid::AccountChange, ActivityId::ACCOUNT_DELETE)
        }

        // Authorize Session (3003) — credential/token issuance
        AuditEventKind::SshCredential
        | AuditEventKind::AwsCredential
        | AuditEventKind::GitHubCredential
        | AuditEventKind::TokenExchange
        | AuditEventKind::OauthTokenIssued => {
            OcsfMapping::new(ClassUid::AuthorizeSession, ActivityId::ASSIGN_PRIVILEGES)
        }
        AuditEventKind::OauthTokenRevoked => {
            OcsfMapping::new(ClassUid::AuthorizeSession, ActivityId::OAUTH_TOKEN_REVOKED)
        }

        // Entity Management (3004) — resource lifecycle: SCIM, OAuth
        // clients, posture policies, API tokens, org domains/keys.
        AuditEventKind::ScimOperation => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::SCIM_OPERATION)
        }
        AuditEventKind::OauthClientRegistered | AuditEventKind::OauthSecretAdded => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_CREATE)
        }
        AuditEventKind::OauthClientUpdated => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_UPDATE)
        }
        AuditEventKind::OauthClientDeleted | AuditEventKind::OauthSecretRevoked => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_DELETE)
        }
        AuditEventKind::AdminPolicyCreate => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_CREATE)
        }
        AuditEventKind::AdminPolicyUpdate | AuditEventKind::AdminPolicyToggle => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_UPDATE)
        }
        AuditEventKind::AdminPolicyDelete => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_DELETE)
        }
        AuditEventKind::AdminCreateScimToken => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_CREATE)
        }
        AuditEventKind::AdminDeleteScimToken | AuditEventKind::AdminRevokeScimToken => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_DELETE)
        }
        AuditEventKind::OrgDomainAdded | AuditEventKind::OrgSubdomainClaimed => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_CREATE)
        }
        AuditEventKind::OrgDomainVerified | AuditEventKind::OrgDomainUnverified => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_UPDATE)
        }
        AuditEventKind::OrgDomainRemoved
        | AuditEventKind::OrgDomainExpired
        | AuditEventKind::OrgSubdomainReleased => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_DELETE)
        }
        AuditEventKind::OrgIssuerKeyRotated => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_UPDATE)
        }
        AuditEventKind::OrgIssuerKeyRevoked => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_DELETE)
        }
        AuditEventKind::OrgIssuerKeyEmergencyRotation => {
            OcsfMapping::new(ClassUid::EntityManagement, ActivityId::ENTITY_UPDATE).medium()
        }
    }
}

/// `metadata.product` per OCSF's base event schema.
#[derive(Serialize)]
struct OcsfProduct {
    name: &'static str,
    vendor_name: &'static str,
}

/// `metadata` per OCSF's base event schema.
#[derive(Serialize)]
pub(crate) struct OcsfMetadata {
    version: &'static str,
    product: OcsfProduct,
}

impl Default for OcsfMetadata {
    fn default() -> Self {
        Self {
            version: OCSF_SCHEMA_VERSION,
            product: OcsfProduct {
                name: "Vouch",
                vendor_name: "Vouch",
            },
        }
    }
}

/// An audit event projected into OCSF's base event shape plus the four IAM
/// classes this mapper targets.
///
/// `data` carries the original event-specific payload verbatim (parsed
/// tolerantly — malformed legacy rows fall back to a JSON string rather
/// than failing serialization) so nothing native-JSON callers can see is
/// lost in the OCSF projection.
#[derive(Serialize)]
pub(crate) struct OcsfEvent {
    /// The stored audit event's own id — OCSF's `uid` attribute. Lets
    /// downstream consumers dedupe re-delivered events across polls.
    pub uid: String,
    pub class_uid: u16,
    pub class_name: &'static str,
    pub category_uid: u16,
    pub category_name: &'static str,
    pub activity_id: ActivityIdValue,
    pub activity_name: &'static str,
    pub type_uid: u32,
    pub severity_id: SeverityId,
    pub severity: &'static str,
    pub status_id: StatusId,
    pub status: &'static str,
    /// Milliseconds since the Unix epoch, per OCSF's `time` attribute.
    pub time: i64,
    pub metadata: OcsfMetadata,
    /// The principal the event is about, when known. OCSF's IAM classes
    /// (3001-3004) all define a `user` attribute; omitted for events with
    /// no user (e.g. `client_credentials` token issuance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<OcsfUser>,
    pub data: RawOrValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<serde_json::Value>,
}

/// Minimal OCSF `user` object: just enough for a SIEM to correlate events
/// by principal. `uid` is Vouch's internal user id — the same value the
/// native JSON response exposes as `user_id`.
#[derive(Serialize)]
pub(crate) struct OcsfUser {
    pub uid: String,
}

/// `activity_id` is serialized as a bare integer, but [`ActivityId`] itself
/// isn't `Copy`-friendly to expose as a public field type across module
/// boundaries — this newtype re-exposes just the integer with the same
/// `Serialize` behavior.
pub(crate) struct ActivityIdValue(u8);

impl Serialize for ActivityIdValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

/// The stored `data` JSON, embedded losslessly via `serde_json`'s
/// `raw_value` feature when it parses, or as a plain JSON string when it
/// doesn't (defensive tolerance for malformed legacy rows — never a 500).
pub(crate) enum RawOrValue {
    Raw(Box<serde_json::value::RawValue>),
    Fallback(serde_json::Value),
}

impl Serialize for RawOrValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Raw(raw) => raw.serialize(serializer),
            Self::Fallback(value) => value.serialize(serializer),
        }
    }
}

/// Parse the stored `data` column tolerantly: valid JSON is embedded
/// byte-for-byte via `RawValue`; anything else falls back to `Value`
/// parsing, and a `Value::Null` as the last resort so this never panics.
pub(crate) fn parse_event_data(data: &str) -> RawOrValue {
    match serde_json::value::RawValue::from_string(data.to_string()) {
        Ok(raw) => RawOrValue::Raw(raw),
        Err(_) => {
            RawOrValue::Fallback(serde_json::from_str(data).unwrap_or(serde_json::Value::Null))
        }
    }
}

/// Project a stored [`AuditEvent`] into its OCSF representation.
///
/// Never fails: an `event_type` that doesn't match a registered
/// [`AuditEventKind`] (a future kind an older binary doesn't know about
/// yet, or corrupted data) becomes an OCSF Base Event with the raw string
/// preserved in `unmapped`, and is logged so it's visible without breaking
/// the response.
pub(crate) fn to_ocsf(event: &AuditEvent) -> OcsfEvent {
    let time = event.created_at.as_millisecond();
    let data = parse_event_data(&event.data);
    let user = event.user_id.clone().map(|uid| OcsfUser { uid });

    let Some(kind) = AuditEventKind::from_wire(&event.event_type) else {
        tracing::warn!(
            event_type = %event.event_type,
            event_id = %event.id,
            "unrecognized audit event_type in OCSF projection; emitting as Base Event"
        );
        return OcsfEvent {
            uid: event.id.clone(),
            class_uid: ClassUid::Base.value(),
            class_name: ClassUid::Base.name(),
            category_uid: CATEGORY_UID_UNCATEGORIZED,
            category_name: CATEGORY_NAME_UNCATEGORIZED,
            activity_id: ActivityIdValue(ActivityId::UNKNOWN.id),
            activity_name: ActivityId::UNKNOWN.name,
            type_uid: 0,
            severity_id: SeverityId::Informational,
            severity: SeverityId::Informational.name(),
            status_id: StatusId::Unknown,
            status: StatusId::Unknown.name(),
            time,
            metadata: OcsfMetadata::default(),
            user,
            data,
            unmapped: Some(serde_json::json!({ "event_type": event.event_type })),
        };
    };

    let mapping = ocsf_class(kind);
    let class_uid = mapping.class.value();
    let type_uid = u32::from(class_uid)
        .saturating_mul(100)
        .saturating_add(u32::from(mapping.activity.id));

    // OCSF 1.9.0: when `activity_id` is `99` (Other), the source-specific
    // activity label must be carried by `activity_name` (handled above via
    // per-event `ActivityId` constants). We additionally preserve the
    // original `event_type` in `unmapped` so SIEM consumers can correlate
    // back to the native Vouch event without parsing the opaque `data`
    // blob — useful for cross-product correlation and schema evolution.
    let unmapped = if mapping.activity.id == 99 {
        Some(serde_json::json!({ "event_type": event.event_type }))
    } else {
        None
    };

    OcsfEvent {
        uid: event.id.clone(),
        class_uid,
        class_name: mapping.class.name(),
        category_uid: CATEGORY_UID_IAM,
        category_name: CATEGORY_NAME_IAM,
        activity_id: ActivityIdValue(mapping.activity.id),
        activity_name: mapping.activity.name,
        type_uid,
        severity_id: mapping.severity,
        severity: mapping.severity.name(),
        status_id: mapping.status,
        status: mapping.status.name(),
        time,
        metadata: OcsfMetadata::default(),
        user,
        data,
        unmapped,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;
    use jiff::Timestamp;

    fn sample_event(kind: AuditEventKind, data: &str) -> AuditEvent {
        AuditEvent {
            id: "01920000-0000-7000-8000-000000000000".to_string(),
            event_type: kind.as_str().to_string(),
            user_id: Some("user-1".to_string()),
            email_domain: Some("example.com".to_string()),
            email_hmac: None,
            data: data.to_string(),
            created_at: Timestamp::now(),
        }
    }

    #[test]
    fn every_kind_maps_to_one_of_the_four_iam_classes() {
        for kind in AuditEventKind::ALL {
            let mapping = ocsf_class(*kind);
            assert!(
                matches!(
                    mapping.class,
                    ClassUid::AccountChange
                        | ClassUid::Authentication
                        | ClassUid::AuthorizeSession
                        | ClassUid::EntityManagement
                ),
                "{kind:?} did not map to a registered IAM class"
            );
        }
    }

    #[test]
    fn type_uid_is_class_uid_times_100_plus_activity_id() {
        let event = sample_event(AuditEventKind::LoginSuccess, "{}");
        let ocsf = to_ocsf(&event);
        assert_eq!(ocsf.class_uid, 3002);
        assert_eq!(ocsf.activity_id.0, 1);
        assert_eq!(ocsf.type_uid, 300201);
    }

    #[test]
    fn unknown_event_type_becomes_base_event_not_an_error() {
        let mut event = sample_event(AuditEventKind::LoginSuccess, "{}");
        event.event_type = "some_future_event_type".to_string();
        let ocsf = to_ocsf(&event);
        assert_eq!(ocsf.class_uid, 0);
        let unmapped = ocsf
            .unmapped
            .expect("unmapped must be set for unknown types");
        assert_eq!(unmapped["event_type"], "some_future_event_type");
    }

    #[test]
    fn malformed_data_falls_back_to_null_not_panic() {
        // Text that is neither valid JSON nor a bare JSON value (e.g. a
        // string) cannot be embedded into a JSON document verbatim without
        // corrupting it — the tolerant fallback is `null`, not a panic or
        // an invalid response body.
        let event = sample_event(AuditEventKind::LoginSuccess, "{not valid json");
        let ocsf = to_ocsf(&event);
        let serialized = serde_json::to_string(&ocsf).expect("must still serialize");
        let value: serde_json::Value =
            serde_json::from_str(&serialized).expect("must be valid JSON");
        assert_eq!(value["data"], serde_json::Value::Null);
    }

    #[test]
    fn valid_data_is_embedded_losslessly() {
        let event = sample_event(AuditEventKind::LoginSuccess, r#"{"success":true,"n":1}"#);
        let ocsf = to_ocsf(&event);
        let serialized = serde_json::to_string(&ocsf).expect("must serialize");
        assert!(serialized.contains(r#""success":true"#));
    }

    #[test]
    fn required_base_fields_are_present() {
        let event = sample_event(AuditEventKind::AdminPromote, "{}");
        let ocsf = to_ocsf(&event);
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ocsf).unwrap()).unwrap();
        for field in [
            "uid",
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "severity_id",
            "status_id",
            "time",
            "metadata",
        ] {
            assert!(value.get(field).is_some(), "missing required field {field}");
        }
    }

    #[test]
    fn event_with_user_id_includes_user_uid() {
        let event = sample_event(AuditEventKind::LoginSuccess, "{}");
        let ocsf = to_ocsf(&event);
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ocsf).unwrap()).unwrap();
        assert_eq!(value["uid"], event.id);
        assert_eq!(value["user"]["uid"], "user-1");
    }

    #[test]
    fn event_without_user_id_omits_user() {
        let mut event = sample_event(AuditEventKind::LoginSuccess, "{}");
        event.user_id = None;
        let ocsf = to_ocsf(&event);
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ocsf).unwrap()).unwrap();
        assert!(value.get("user").is_none());
    }

    #[test]
    fn login_failed_is_medium_severity_and_failure_status() {
        let event = sample_event(AuditEventKind::LoginFailed, "{}");
        let ocsf = to_ocsf(&event);
        assert_eq!(ocsf.status_id.value(), StatusId::Failure.value());
        assert_eq!(ocsf.severity_id.value(), SeverityId::Medium.value());
    }

    /// OCSF 1.9.0: when `activity_id` is `99` (Other), `activity_name`
    /// **must** carry a source-specific label (not the literal "Other"),
    /// and we additionally preserve the original `event_type` in
    /// `unmapped` so SIEM consumers can distinguish these events at the
    /// OCSF classification layer without parsing the opaque `data` blob.
    #[test]
    fn activity_id_99_events_have_source_specific_name_and_unmapped_event_type() {
        let cases: [(AuditEventKind, u16, &str); 5] = [
            (AuditEventKind::AdminPromote, 3001, "Admin Promote"),
            (AuditEventKind::AdminDemote, 3001, "Admin Demote"),
            (
                AuditEventKind::AdminRevokeCredentials,
                3001,
                "Admin Revoke Credentials",
            ),
            (
                AuditEventKind::OauthTokenRevoked,
                3003,
                "OAuth Token Revoked",
            ),
            (AuditEventKind::ScimOperation, 3004, "SCIM Operation"),
        ];

        for (kind, expected_class_uid, expected_activity_name) in cases {
            let event = sample_event(kind, "{}");
            let ocsf = to_ocsf(&event);
            assert_eq!(
                ocsf.activity_id.0, 99,
                "{kind:?}: activity_id must be 99 (Other)"
            );
            assert_ne!(
                ocsf.activity_name, "Other",
                "{kind:?}: activity_name must be source-specific, not the generic \"Other\""
            );
            assert_eq!(
                ocsf.activity_name, expected_activity_name,
                "{kind:?}: activity_name mismatch"
            );
            assert_eq!(
                ocsf.class_uid, expected_class_uid,
                "{kind:?}: class_uid mismatch"
            );
            // type_uid is class_uid * 100 + activity_id, so 300199, 300399, 300499.
            assert_eq!(
                ocsf.type_uid,
                u32::from(expected_class_uid) * 100 + 99,
                "{kind:?}: type_uid must reflect activity_id 99"
            );
            // The original Vouch event_type must be preserved in unmapped
            // for cross-product correlation without parsing `data`.
            let unmapped = ocsf
                .unmapped
                .as_ref()
                .expect("unmapped must be populated for activity_id 99");
            assert_eq!(
                unmapped["event_type"],
                kind.as_str(),
                "{kind:?}: unmapped.event_type must preserve the source event_type"
            );
        }
    }

    /// Regression guard: `AdminPromote` and `AdminDemote` are opposite
    /// security-relevant actions within the Account Change class. Before
    /// the fix they were indistinguishable at the OCSF layer (both
    /// `activity_id: 99`, `activity_name: "Other"`). They must now carry
    /// distinct `activity_name` values.
    #[test]
    fn admin_promote_and_demote_are_distinguishable_at_ocsf_layer() {
        let promote = to_ocsf(&sample_event(AuditEventKind::AdminPromote, "{}"));
        let demote = to_ocsf(&sample_event(AuditEventKind::AdminDemote, "{}"));
        assert_eq!(promote.class_uid, demote.class_uid);
        assert_eq!(promote.activity_id.0, demote.activity_id.0);
        assert_ne!(
            promote.activity_name, demote.activity_name,
            "AdminPromote and AdminDemote must be distinguishable by activity_name"
        );
        assert_ne!(
            promote.unmapped, demote.unmapped,
            "AdminPromote and AdminDemote must be distinguishable by unmapped.event_type"
        );
    }

    /// Regression guard: events that map to a non-99 `activity_id` must
    /// NOT populate `unmapped` — it's only for unrecognized wire strings
    /// and the activity_id: 99 escape hatch.
    #[test]
    fn non_other_activities_do_not_populate_unmapped() {
        for kind in AuditEventKind::ALL {
            let ocsf = to_ocsf(&sample_event(*kind, "{}"));
            if ocsf.activity_id.0 == 99 {
                assert!(
                    ocsf.unmapped.is_some(),
                    "{kind:?}: activity_id 99 must populate unmapped"
                );
            } else {
                assert!(
                    ocsf.unmapped.is_none(),
                    "{kind:?}: non-99 activity_id must not populate unmapped (got {:?})",
                    ocsf.unmapped
                );
            }
        }
    }

    /// OCSF 1.9.0 MUST: no event may serialize `activity_name` as the
    /// literal "Other" — that's the spec's explicit anti-pattern for
    /// `activity_id: 99`. Sweep every kind to be sure.
    #[test]
    fn no_event_serializes_activity_name_as_literal_other() {
        for kind in AuditEventKind::ALL {
            let ocsf = to_ocsf(&sample_event(*kind, "{}"));
            assert_ne!(
                ocsf.activity_name, "Other",
                "{kind:?}: activity_name must never be the literal \"Other\""
            );
        }
    }

    /// Parity guard: the "## OCSF Mapping" table in `docs/src/admin/audit.md`
    /// must agree with [`ocsf_class`] for every registered kind. Parses the
    /// docs table rather than duplicating a second hardcoded mapping in the
    /// test, so the only way to change the mapping without this test
    /// catching a mismatch is to also update the docs.
    #[test]
    fn docs_ocsf_mapping_table_matches_code() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/src/admin/audit.md");
        let doc = std::fs::read_to_string(path).expect("read audit.md");
        let start = doc
            .find("## OCSF Mapping")
            .expect("audit.md must have an '## OCSF Mapping' section");
        let section = doc.get(start..).expect("section start is a char boundary");

        let mut documented: std::collections::HashMap<String, u16> =
            std::collections::HashMap::new();
        for line in section.lines().filter(|l| l.trim_start().starts_with('|')) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            // Row shape: | `event_type` | 3002 | Authentication |
            if cells.len() < 4 {
                continue;
            }
            let event_type = cells[1].trim_matches('`');
            let Ok(class_uid) = cells[2].parse::<u16>() else {
                continue;
            };
            if AuditEventKind::from_wire(event_type).is_some() {
                documented.insert(event_type.to_string(), class_uid);
            }
        }

        assert_eq!(
            documented.len(),
            AuditEventKind::ALL.len(),
            "docs/src/admin/audit.md '## OCSF Mapping' table must list every AuditEventKind \
             (found {}, expected {})",
            documented.len(),
            AuditEventKind::ALL.len()
        );

        for kind in AuditEventKind::ALL {
            let documented_class_uid = documented.get(kind.as_str());
            assert!(
                documented_class_uid.is_some(),
                "{} missing from docs OCSF Mapping table",
                kind.as_str()
            );
            let documented_class_uid = documented_class_uid.expect("checked above");
            let code_class_uid = ocsf_class(*kind).class.value();
            assert_eq!(
                *documented_class_uid,
                code_class_uid,
                "docs OCSF Mapping table says {} maps to class_uid {documented_class_uid}, \
                 but ocsf_class() maps it to {code_class_uid}",
                kind.as_str()
            );
        }
    }
}
