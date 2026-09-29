// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The policy-builder catalog: every field, operator, and history event the
//! admin UI may offer, with the type information that decides which
//! operators fit.
//!
//! This is the single machine-readable description of the policy surface.
//! [`DEVICE_FIELDS`] mirrors the `Device` record in `vouch.cedarschema` and
//! [`posture_input::posture_fields`]; the field-parity test asserts the
//! three agree, so the builder, the generated reference table, and the
//! engine cannot drift apart. [`HISTORY_EVENTS`] mirrors the audit → event
//! ingestion in [`events::history_event`].
//!
//! [`posture_input::posture_fields`]: super::posture_input::posture_fields
//! [`events::history_event`]: super::events::history_event

use crate::infra::i18n::Tr;
use dogwood_language::Value;
use serde::Deserialize;
use vouch_common::posture::{DevicePosture, EdrAgent, MdmAgent, OperatingSystem, PostureTypeTag};

/// Maximum stored policy text length in Unicode characters, shared by the
/// form guard, the JSON validate endpoint, and the generator's `TooLong`
/// check. Counted in characters rather than UTF-8 bytes so the limit matches
/// the `maxlength` the textarea advertises and the number the error names.
pub(crate) const MAX_POLICY_TEXT_LEN: usize = 4096;

/// The temporal window cap in hours, mirroring Dogwood's default
/// `max_window` (24h). The builder's window control clamps to this; the
/// validator enforces it on every `within` interval regardless.
pub(crate) const MAX_WINDOW_HOURS: u64 = 24;

/// [`MAX_WINDOW_HOURS`] in seconds; the parity tests assert the two agree
/// with the replay window.
pub(crate) const MAX_WINDOW_SECS: u64 = 86_400;

/// Which enforcement point a policy gates. Only token issuance carries the
/// request-only `device` context group, so device conditions are offered —
/// and generated — for [`Self::IssueToken`] alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionPoint {
    IssueToken,
    ExchangeToken,
}

impl DecisionPoint {
    /// The fully qualified Cedar action name.
    pub(crate) const fn action_name(self) -> &'static str {
        match self {
            Self::IssueToken => "Vouch::Action::IssueToken",
            Self::ExchangeToken => "Vouch::Action::ExchangeToken",
        }
    }

    /// The quoted form used inside policy text.
    pub(crate) const fn action_literal(self) -> &'static str {
        match self {
            Self::IssueToken => "Vouch::Action::\"IssueToken\"",
            Self::ExchangeToken => "Vouch::Action::\"ExchangeToken\"",
        }
    }

    /// Whether `context.device` exists at this decision point.
    pub(crate) const fn allows_device(self) -> bool {
        match self {
            Self::IssueToken => true,
            Self::ExchangeToken => false,
        }
    }
}

/// The type of a device field, which decides the operators and value
/// control the builder offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldKind {
    Bool,
    Long,
    /// Free-form string (self-attested, no closed value list).
    Text,
    /// String drawn from a closed enum; the values are the only ones a
    /// client can report.
    TextEnum(&'static [&'static str]),
    /// Set of strings drawn from a closed enum.
    StringSet(&'static [&'static str]),
    /// Encoded version number derived from a raw string field
    /// (`major * 1_000_000 + minor * 1_000 + patch`, `-1` unparseable).
    VersionNum {
        source: &'static str,
    },
    /// Numeric build derived from a raw string field (`-1` unparseable).
    BuildNum {
        source: &'static str,
    },
}

impl FieldKind {
    /// Wire tag for the builder's catalog JSON.
    pub(crate) const fn wire(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Long => "long",
            Self::Text => "text",
            Self::TextEnum(_) => "text_enum",
            Self::StringSet(_) => "string_set",
            Self::VersionNum { .. } => "version_num",
            Self::BuildNum { .. } => "build_num",
        }
    }

    /// The closed value list, when the kind has one.
    pub(crate) const fn known_values(self) -> Option<&'static [&'static str]> {
        match self {
            Self::TextEnum(values) | Self::StringSet(values) => Some(values),
            Self::Bool
            | Self::Long
            | Self::Text
            | Self::VersionNum { .. }
            | Self::BuildNum { .. } => None,
        }
    }
}

/// Display grouping for the field dropdown and the reference table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldGroup {
    Os,
    Security,
    Agents,
    Process,
    Meta,
}

impl FieldGroup {
    /// Every group, in display order.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Os,
        Self::Security,
        Self::Agents,
        Self::Process,
        Self::Meta,
    ];

    pub(crate) const fn wire(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Security => "security",
            Self::Agents => "agents",
            Self::Process => "process",
            Self::Meta => "meta",
        }
    }

    fn label(self) -> String {
        match self {
            Self::Os => Tr::new("admin-policies-group-os").to_string(),
            Self::Security => Tr::new("admin-policies-group-security").to_string(),
            Self::Agents => Tr::new("admin-policies-group-agents").to_string(),
            Self::Process => Tr::new("admin-policies-group-process").to_string(),
            Self::Meta => Tr::new("admin-policies-group-meta").to_string(),
        }
    }
}

/// One device field the builder may condition on.
pub(crate) struct FieldMeta {
    /// The `context.device.<name>` identifier — shown verbatim in the UI so
    /// the builder teaches the same names raw policy text uses.
    pub name: &'static str,
    pub kind: FieldKind,
    pub group: FieldGroup,
    /// A validated example check, true for the field-parity test's fixture
    /// device. The parity test lowers, validates, and evaluates each one.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the field-parity test only")
    )]
    pub sample_check: &'static str,
}

/// Every field of the `Device` record, in schema order. The field-parity
/// test asserts this list matches `posture_fields()` exactly, name and type.
pub(crate) const DEVICE_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "os",
        kind: FieldKind::TextEnum(OperatingSystem::ALL),
        group: FieldGroup::Os,
        sample_check: "context.device.os == \"macos\"",
    },
    FieldMeta {
        name: "os_version",
        kind: FieldKind::Text,
        group: FieldGroup::Os,
        sample_check: "context.device.os_version == \"15.3.1\"",
    },
    FieldMeta {
        name: "os_version_num",
        kind: FieldKind::VersionNum {
            source: "os_version",
        },
        group: FieldGroup::Os,
        sample_check: "context.device.os_version_num == 15003001",
    },
    FieldMeta {
        name: "os_distribution",
        kind: FieldKind::Text,
        group: FieldGroup::Os,
        sample_check: "context.device.os_distribution == \"macos\"",
    },
    FieldMeta {
        name: "os_build",
        kind: FieldKind::Text,
        group: FieldGroup::Os,
        sample_check: "context.device.os_build == \"26100\"",
    },
    FieldMeta {
        name: "os_build_num",
        kind: FieldKind::BuildNum { source: "os_build" },
        group: FieldGroup::Os,
        sample_check: "context.device.os_build_num == 26100",
    },
    FieldMeta {
        name: "arch",
        kind: FieldKind::Text,
        group: FieldGroup::Os,
        sample_check: "context.device.arch == \"aarch64\"",
    },
    FieldMeta {
        name: "disk_encryption_enabled",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.disk_encryption_enabled",
    },
    FieldMeta {
        name: "disk_encryption_technology",
        kind: FieldKind::Text,
        group: FieldGroup::Security,
        sample_check: "context.device.disk_encryption_technology == \"filevault\"",
    },
    FieldMeta {
        name: "screen_lock_enabled",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.screen_lock_enabled",
    },
    FieldMeta {
        name: "screen_lock_idle_timeout_secs",
        kind: FieldKind::Long,
        group: FieldGroup::Security,
        sample_check: "context.device.screen_lock_idle_timeout_secs == 300",
    },
    FieldMeta {
        name: "firewall_enabled",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.firewall_enabled",
    },
    FieldMeta {
        name: "firewall_technology",
        kind: FieldKind::Text,
        group: FieldGroup::Security,
        sample_check: "context.device.firewall_technology == \"application firewall\"",
    },
    FieldMeta {
        name: "secure_boot_enabled",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.secure_boot_enabled",
    },
    FieldMeta {
        name: "sip_enabled",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.sip_enabled",
    },
    FieldMeta {
        name: "tpm_present",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.tpm_present",
    },
    FieldMeta {
        name: "tpm_version",
        kind: FieldKind::Text,
        group: FieldGroup::Security,
        sample_check: "context.device.tpm_version == \"2.0\"",
    },
    FieldMeta {
        name: "auto_update_enabled",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.auto_update_enabled",
    },
    FieldMeta {
        name: "auto_update_technology",
        kind: FieldKind::Text,
        group: FieldGroup::Security,
        sample_check: "context.device.auto_update_technology == \"softwareupdate\"",
    },
    FieldMeta {
        name: "uptime_secs",
        kind: FieldKind::Long,
        group: FieldGroup::Security,
        sample_check: "context.device.uptime_secs == 86400",
    },
    FieldMeta {
        name: "access_control_enforcing",
        kind: FieldKind::Bool,
        group: FieldGroup::Security,
        sample_check: "context.device.access_control_enforcing",
    },
    FieldMeta {
        name: "access_control_technology",
        kind: FieldKind::Text,
        group: FieldGroup::Security,
        sample_check: "context.device.access_control_technology == \"gatekeeper\"",
    },
    FieldMeta {
        name: "edr",
        kind: FieldKind::StringSet(EdrAgent::ALL),
        group: FieldGroup::Agents,
        sample_check: "context.device.edr.contains(\"crowdstrike\")",
    },
    FieldMeta {
        name: "edr_count",
        kind: FieldKind::Long,
        group: FieldGroup::Agents,
        sample_check: "context.device.edr_count == 1",
    },
    FieldMeta {
        name: "mdm",
        kind: FieldKind::StringSet(MdmAgent::ALL),
        group: FieldGroup::Agents,
        sample_check: "context.device.mdm.contains(\"jamf\")",
    },
    FieldMeta {
        name: "mdm_count",
        kind: FieldKind::Long,
        group: FieldGroup::Agents,
        sample_check: "context.device.mdm_count == 1",
    },
    FieldMeta {
        name: "elevated",
        kind: FieldKind::Bool,
        group: FieldGroup::Process,
        sample_check: "context.device.elevated == false",
    },
    FieldMeta {
        name: "tty",
        kind: FieldKind::Bool,
        group: FieldGroup::Process,
        sample_check: "context.device.tty",
    },
    FieldMeta {
        name: "parent_process",
        kind: FieldKind::Text,
        group: FieldGroup::Process,
        sample_check: "context.device.parent_process == \"zsh\"",
    },
    FieldMeta {
        name: "cli_version",
        kind: FieldKind::Text,
        group: FieldGroup::Meta,
        sample_check: "context.device.cli_version == \"1.2.3\"",
    },
    FieldMeta {
        name: "collected_at",
        kind: FieldKind::Text,
        group: FieldGroup::Meta,
        sample_check: "context.device.collected_at == \"2026-08-08t00:00:00z\"",
    },
];

/// Look up a device field by its schema name.
pub(crate) fn device_field(name: &str) -> Option<&'static FieldMeta> {
    DEVICE_FIELDS.iter().find(|f| f.name == name)
}

/// A comparison operator the builder can emit. Which operators a field
/// offers is decided by its [`FieldKind`] via [`Operator::allowed_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operator {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
    Contains,
    NotContains,
}

impl Operator {
    /// The operators a field kind admits, in display order.
    pub(crate) const fn allowed_for(kind: FieldKind) -> &'static [Self] {
        match kind {
            FieldKind::Bool => &[Self::Eq],
            FieldKind::Long | FieldKind::VersionNum { .. } | FieldKind::BuildNum { .. } => {
                &[Self::Ge, Self::Le, Self::Eq, Self::Ne, Self::Gt, Self::Lt]
            }
            FieldKind::Text | FieldKind::TextEnum(_) => &[Self::Eq, Self::Ne],
            FieldKind::StringSet(_) => &[Self::Contains, Self::NotContains],
        }
    }

    pub(crate) const fn wire(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Ge => "ge",
            Self::Le => "le",
            Self::Gt => "gt",
            Self::Lt => "lt",
            Self::Contains => "contains",
            Self::NotContains => "not_contains",
        }
    }

    /// The Cedar comparison token, for operators that are plain infix
    /// comparisons (`Contains`/`NotContains` render as method calls).
    pub(crate) const fn cedar_infix(self) -> Option<&'static str> {
        match self {
            Self::Eq => Some("=="),
            Self::Ne => Some("!="),
            Self::Ge => Some(">="),
            Self::Le => Some("<="),
            Self::Gt => Some(">"),
            Self::Lt => Some("<"),
            Self::Contains | Self::NotContains => None,
        }
    }

    /// Label shown in the operator dropdown. Symbols are language-neutral;
    /// the word operators come from the catalog.
    fn label(self) -> String {
        match self {
            Self::Eq => "=".to_string(),
            Self::Ne => "\u{2260}".to_string(),
            Self::Ge => "\u{2265}".to_string(),
            Self::Le => "\u{2264}".to_string(),
            Self::Gt => ">".to_string(),
            Self::Lt => "<".to_string(),
            Self::Contains => Tr::new("admin-policies-op-contains").to_string(),
            Self::NotContains => Tr::new("admin-policies-op-not-contains").to_string(),
        }
    }
}

/// A field pin on a history atom, e.g. `output.result: true` selecting
/// successful logins.
pub(crate) struct Pin {
    /// The `group.field` path inside the atom's pin record.
    pub path: &'static str,
    pub value: PinValue,
}

pub(crate) enum PinValue {
    Bool(bool),
    Str(&'static str),
}

/// One history event kind the builder can condition on. Each entry pairs a
/// Cedar action with the pins that select it — the same mapping
/// [`events::history_event`] writes when ingesting audit rows, which the
/// parity test cross-checks.
///
/// [`events::history_event`]: super::events::history_event
pub(crate) struct HistoryEventMeta {
    /// Wire key used in a `RuleSpec` and the catalog JSON.
    pub key: &'static str,
    /// Fully qualified action, quoted form (`Vouch::Action::"Login"`).
    pub action_literal: &'static str,
    pub pins: &'static [Pin],
    /// i18n key for the sentence-level label ("successful login").
    pub label_key: &'static str,
}

/// Every history event the builder offers — one per ingested audit kind.
pub(crate) const HISTORY_EVENTS: &[HistoryEventMeta] = &[
    HistoryEventMeta {
        key: "login_success",
        action_literal: "Vouch::Action::\"Login\"",
        pins: &[Pin {
            path: "output.result",
            value: PinValue::Bool(true),
        }],
        label_key: "admin-policies-event-login-success",
    },
    HistoryEventMeta {
        key: "login_failed",
        action_literal: "Vouch::Action::\"Login\"",
        pins: &[Pin {
            path: "output.result",
            value: PinValue::Bool(false),
        }],
        label_key: "admin-policies-event-login-failed",
    },
    HistoryEventMeta {
        key: "logout",
        action_literal: "Vouch::Action::\"Logout\"",
        pins: &[],
        label_key: "admin-policies-event-logout",
    },
    HistoryEventMeta {
        key: "token_issued",
        action_literal: "Vouch::Action::\"IssueToken\"",
        pins: &[],
        label_key: "admin-policies-event-token-issued",
    },
    HistoryEventMeta {
        key: "token_revoked",
        action_literal: "Vouch::Action::\"RevokeToken\"",
        pins: &[],
        label_key: "admin-policies-event-token-revoked",
    },
    HistoryEventMeta {
        key: "token_exchange",
        action_literal: "Vouch::Action::\"ExchangeToken\"",
        pins: &[],
        label_key: "admin-policies-event-token-exchange",
    },
    HistoryEventMeta {
        key: "ssh_credential",
        action_literal: "Vouch::Action::\"IssueCredential\"",
        pins: &[Pin {
            path: "input.kind",
            value: PinValue::Str("ssh"),
        }],
        label_key: "admin-policies-event-ssh-credential",
    },
    HistoryEventMeta {
        key: "aws_credential",
        action_literal: "Vouch::Action::\"IssueCredential\"",
        pins: &[Pin {
            path: "input.kind",
            value: PinValue::Str("aws"),
        }],
        label_key: "admin-policies-event-aws-credential",
    },
    HistoryEventMeta {
        key: "github_credential",
        action_literal: "Vouch::Action::\"IssueCredential\"",
        pins: &[Pin {
            path: "input.kind",
            value: PinValue::Str("github"),
        }],
        label_key: "admin-policies-event-github-credential",
    },
];

/// Look up a history event by its wire key.
pub(crate) fn history_event_meta(key: &str) -> Option<&'static HistoryEventMeta> {
    HISTORY_EVENTS.iter().find(|e| e.key == key)
}

/// One matchable field on a history event's pin record.
pub(crate) struct EventFieldMeta {
    /// The `group.field` path (`input.ip`, `output.result`).
    pub path: &'static str,
    pub kind: FieldKind,
}

/// The fields a temporal predicate can match on one action's `::response`
/// events — the same fields ingestion writes, which the event-reference
/// parity test enforces. When the action is the decision being evaluated,
/// the same `input` record is readable as `context.input.*`.
pub(crate) struct ActionFieldsMeta {
    /// Bare action name (`Login`), displayed as
    /// `Vouch::Action::"Login"::response`.
    pub action: &'static str,
    pub fields: &'static [EventFieldMeta],
}

/// Every ingested history action and its matchable fields, for the
/// generated reference. `AgentToolCall` is schema-declared but not
/// ingested, so it is deliberately absent.
pub(crate) const HISTORY_ACTION_FIELDS: &[ActionFieldsMeta] = &[
    ActionFieldsMeta {
        action: "Login",
        fields: &[
            EventFieldMeta {
                path: "input.ip",
                kind: FieldKind::Text,
            },
            EventFieldMeta {
                path: "input.user_agent",
                kind: FieldKind::Text,
            },
            EventFieldMeta {
                path: "output.result",
                kind: FieldKind::Bool,
            },
        ],
    },
    ActionFieldsMeta {
        action: "IssueToken",
        fields: &[
            EventFieldMeta {
                path: "input.ip",
                kind: FieldKind::Text,
            },
            EventFieldMeta {
                path: "input.client_id",
                kind: FieldKind::Text,
            },
        ],
    },
    ActionFieldsMeta {
        action: "ExchangeToken",
        fields: &[
            EventFieldMeta {
                path: "input.ip",
                kind: FieldKind::Text,
            },
            EventFieldMeta {
                path: "input.client_id",
                kind: FieldKind::Text,
            },
            EventFieldMeta {
                path: "input.audience",
                kind: FieldKind::Text,
            },
        ],
    },
    ActionFieldsMeta {
        action: "Logout",
        fields: &[],
    },
    ActionFieldsMeta {
        action: "RevokeToken",
        fields: &[],
    },
    ActionFieldsMeta {
        action: "IssueCredential",
        fields: &[EventFieldMeta {
            path: "input.kind",
            kind: FieldKind::TextEnum(&["ssh", "aws", "github"]),
        }],
    },
];

/// A field row of the generated event reference.
pub(crate) struct EventRefField {
    pub path: &'static str,
    pub type_label: String,
}

/// One action of the generated event reference.
pub(crate) struct EventRefGroup {
    pub action: &'static str,
    pub fields: Vec<EventRefField>,
}

/// The event reference, with type labels translated.
pub(crate) fn event_reference_groups() -> Vec<EventRefGroup> {
    HISTORY_ACTION_FIELDS
        .iter()
        .map(|a| EventRefGroup {
            action: a.action,
            fields: a
                .fields
                .iter()
                .map(|f| EventRefField {
                    path: f.path,
                    type_label: type_label(f.kind),
                })
                .collect(),
        })
        .collect()
}

/// The device the playground evaluates against when the caller supplies no
/// posture: a healthy macOS laptop. The full struct literal (no
/// `..Default::default()`) is deliberate — adding a posture field breaks
/// this function at compile time, alongside `posture_fields`.
pub(crate) fn sample_posture() -> DevicePosture {
    DevicePosture {
        detail_type: PostureTypeTag,
        posture_version: 1,
        os: Some(OperatingSystem::MacOs),
        os_version: Some("26.3.1".to_string()),
        os_distribution: Some("macos".to_string()),
        os_build: Some("25d2128".to_string()),
        arch: Some("aarch64".to_string()),
        disk_encryption_enabled: Some(true),
        disk_encryption_technology: Some("filevault".to_string()),
        screen_lock_enabled: Some(true),
        screen_lock_idle_timeout_secs: Some(300),
        firewall_enabled: Some(true),
        firewall_technology: Some("application firewall".to_string()),
        secure_boot_enabled: Some(true),
        sip_enabled: Some(true),
        tpm_present: Some(true),
        tpm_version: Some("2.0".to_string()),
        auto_update_enabled: Some(true),
        auto_update_technology: Some("softwareupdate".to_string()),
        uptime_secs: Some(86_400),
        access_control_enforcing: Some(true),
        access_control_technology: Some("gatekeeper".to_string()),
        edr: vec![EdrAgent::CrowdStrike],
        mdm: vec![MdmAgent::Jamf],
        elevated: Some(false),
        tty: Some(true),
        parent_process: Some("zsh".to_string()),
        cli_version: Some("2026.3.11".to_string()),
        collected_at: Some("2026-08-08T00:00:00Z".to_string()),
    }
}

/// The catalog the builder JS reads, serialized with labels already
/// translated for the request's locale (which is why the builder needs
/// almost nothing in `JS_I18N_KEYS`).
pub(crate) fn catalog_json() -> String {
    let fields: Vec<serde_json::Value> = DEVICE_FIELDS
        .iter()
        .map(|f| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".to_string(), serde_json::json!(f.name));
            obj.insert("kind".to_string(), serde_json::json!(f.kind.wire()));
            obj.insert("group".to_string(), serde_json::json!(f.group.wire()));
            if let Some(values) = f.kind.known_values() {
                obj.insert("values".to_string(), serde_json::json!(values));
            }
            if let FieldKind::VersionNum { source } | FieldKind::BuildNum { source } = f.kind {
                obj.insert("source".to_string(), serde_json::json!(source));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let events: Vec<serde_json::Value> = HISTORY_EVENTS
        .iter()
        .map(|e| {
            serde_json::json!({
                "key": e.key,
                "label": Tr::new(e.label_key).to_string(),
            })
        })
        .collect();

    let operator_entry = |op: Operator| serde_json::json!({ "op": op.wire(), "label": op.label() });
    let mut operators = serde_json::Map::new();
    for kind in [
        FieldKind::Bool,
        FieldKind::Long,
        FieldKind::Text,
        FieldKind::TextEnum(&[]),
        FieldKind::StringSet(&[]),
        FieldKind::VersionNum { source: "" },
        FieldKind::BuildNum { source: "" },
    ] {
        let ops: Vec<serde_json::Value> = Operator::allowed_for(kind)
            .iter()
            .map(|op| operator_entry(*op))
            .collect();
        operators.insert(kind.wire().to_string(), serde_json::Value::Array(ops));
    }

    let mut groups = serde_json::Map::new();
    for group in FieldGroup::ALL {
        groups.insert(
            group.wire().to_string(),
            serde_json::Value::String(group.label()),
        );
    }

    serde_json::json!({
        "fields": fields,
        "events": events,
        "operators": operators,
        "groups": groups,
        "max_window_hours": MAX_WINDOW_HOURS,
        "max_policy_len": MAX_POLICY_TEXT_LEN,
    })
    .to_string()
}

/// A row of the generated field-reference table.
pub(crate) struct FieldRefRow {
    pub name: &'static str,
    pub type_label: String,
    pub sample: String,
}

/// One group of the generated field-reference table.
pub(crate) struct FieldRefGroup {
    pub label: String,
    pub rows: Vec<FieldRefRow>,
}

/// The reference table, grouped with translated headings, valued from the
/// same sample device the playground tests against.
pub(crate) fn field_reference_groups() -> Vec<FieldRefGroup> {
    let record = super::posture_input::posture_fields(&sample_posture());
    FieldGroup::ALL
        .iter()
        .map(|group| FieldRefGroup {
            label: group.label(),
            rows: DEVICE_FIELDS
                .iter()
                .filter(|f| f.group == *group)
                .map(|f| FieldRefRow {
                    name: f.name,
                    type_label: type_label(f.kind),
                    sample: record.get(f.name).map(render_value).unwrap_or_default(),
                })
                .collect(),
        })
        .collect()
}

fn type_label(kind: FieldKind) -> String {
    match kind {
        FieldKind::Bool => Tr::new("admin-policies-type-bool").to_string(),
        FieldKind::Long => Tr::new("admin-policies-type-long").to_string(),
        FieldKind::Text => Tr::new("admin-policies-type-text").to_string(),
        FieldKind::TextEnum(values) => Tr::new("admin-policies-type-text-enum")
            .arg("values", values.join(" | "))
            .to_string(),
        FieldKind::StringSet(values) => Tr::new("admin-policies-type-set")
            .arg("values", values.join(", "))
            .to_string(),
        FieldKind::VersionNum { source } | FieldKind::BuildNum { source } => {
            Tr::new("admin-policies-type-derived-num")
                .arg("source", source)
                .to_string()
        }
    }
}

/// Render a context value as it would appear in policy text.
fn render_value(value: &Value) -> String {
    match value {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::String(s) => format!("\"{s}\""),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(render_value).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Null | Value::Decimal(_) | Value::Entity { .. } | Value::Object(_) => String::new(),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code: panic on assertion failure is acceptable"
)]
mod tests {
    use super::*;

    /// Every history-event label key resolves in the catalog. The literal
    /// `Tr::new("…")` calls are what the i18n enforcement test scans for,
    /// and the assertions bind each literal to the const entry that uses
    /// it, so the two cannot drift.
    #[test]
    fn history_event_label_keys_resolve() {
        let literals = [
            (
                "login_success",
                Tr::new("admin-policies-event-login-success").to_string(),
            ),
            (
                "login_failed",
                Tr::new("admin-policies-event-login-failed").to_string(),
            ),
            ("logout", Tr::new("admin-policies-event-logout").to_string()),
            (
                "token_issued",
                Tr::new("admin-policies-event-token-issued").to_string(),
            ),
            (
                "token_revoked",
                Tr::new("admin-policies-event-token-revoked").to_string(),
            ),
            (
                "token_exchange",
                Tr::new("admin-policies-event-token-exchange").to_string(),
            ),
            (
                "ssh_credential",
                Tr::new("admin-policies-event-ssh-credential").to_string(),
            ),
            (
                "aws_credential",
                Tr::new("admin-policies-event-aws-credential").to_string(),
            ),
            (
                "github_credential",
                Tr::new("admin-policies-event-github-credential").to_string(),
            ),
        ];
        assert_eq!(
            literals.len(),
            HISTORY_EVENTS.len(),
            "one literal per catalog event"
        );
        for (key, rendered) in literals {
            let meta = history_event_meta(key).unwrap();
            assert_eq!(
                Tr::new(meta.label_key).to_string(),
                rendered,
                "label_key for '{key}' must be the literal asserted here"
            );
            assert_ne!(
                rendered, meta.label_key,
                "label for '{key}' must not render as the raw key"
            );
        }
    }

    /// Group labels resolve (not raw keys), and the catalog JSON parses.
    #[test]
    fn group_labels_and_catalog_json_resolve() {
        for group in FieldGroup::ALL {
            assert_ne!(group.label(), String::new());
            assert!(!group.label().starts_with("admin-policies-"));
        }
        let parsed: serde_json::Value = serde_json::from_str(&catalog_json()).unwrap();
        assert_eq!(
            parsed["fields"].as_array().unwrap().len(),
            DEVICE_FIELDS.len()
        );
        assert_eq!(
            parsed["events"].as_array().unwrap().len(),
            HISTORY_EVENTS.len()
        );
        assert_eq!(parsed["max_window_hours"], 24);
    }
}
