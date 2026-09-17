// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Table-driven applier for SCIM PATCH operations (RFC 7644 §3.5.2).
//!
//! A resource declares the single-valued attributes it stores as a table of
//! [`Attribute`] entries: the paths that address the attribute, how a
//! presented value is stored, and what a removal does. [`apply_patch_op`]
//! applies `add`, `replace`, and `remove` against that table, so a resource
//! never states the operation semantics itself and the three operations
//! cannot diverge attribute by attribute.
//!
//! The semantics [`apply_patch_op`] implements:
//!
//! - `add` and `replace` both store the presented value: on a single-valued
//!   attribute an `add` replaces (§3.5.2.1).
//! - `add` and `replace` carry a `value`; one without is 400 `invalidValue`
//!   (§3.5.2.1: "The operation MUST contain a "value" member"). Every
//!   applier takes a [`PatchOp`], which cannot hold an `add` or `replace`
//!   without one.
//! - `remove` clears the stored value (§3.5.2.2). Removing a required
//!   attribute is 400 `mutability`, as §3.5.2.2 requires; the attribute's
//!   `remove` entry says so.
//! - An operation with no `path` merges every attribute its value object
//!   presents, each addressed by its dotted path (`name.formatted` reads
//!   `{"name": {"formatted": …}}`), matching names case-insensitively.
//! - A pathless `remove` is 400 `noTarget` (§3.5.2.2: "If "path" is
//!   unspecified, the operation fails with HTTP status code 400 and a
//!   "scimType" error code of "noTarget"").
//! - A path no entry claims is ignored and the request still succeeds.
//!   Identity providers PATCH attributes Vouch does not store — `title`,
//!   `department`, `name.givenName`, enterprise-extension URNs — and
//!   rejecting those fails the whole provisioning sync at the IdP over an
//!   attribute the directory was never going to persist. RFC 7644 §3.1 has
//!   the service provider interpret a request against its own schema, and
//!   `/Schemas` does not list these.
//!
//! Multi-valued attributes (Group `members`) have no table entry: they are
//! stored outside the resource document and are applied by their handler
//! before the operation reaches [`apply_patch_op`].

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use super::types::{ScimError, ScimPatchOp, ScimPatchOpType};

/// A write an attribute cannot accept, reported as a SCIM 400 with the
/// RFC 7644 §3.12 Table 9 `scimType` naming why.
pub(crate) struct AttributeError {
    pub(crate) scim_type: &'static str,
    detail: String,
}

impl AttributeError {
    /// The value is not compatible with the attribute's type or schema.
    pub(crate) fn invalid_value(detail: impl Into<String>) -> Self {
        Self {
            scim_type: "invalidValue",
            detail: detail.into(),
        }
    }

    /// The write is not compatible with the attribute's mutability, such as
    /// a different value for an `immutable` attribute or the removal of a
    /// required one.
    pub(crate) fn mutability(detail: impl Into<String>) -> Self {
        Self {
            scim_type: "mutability",
            detail: detail.into(),
        }
    }

    /// The request body does not conform to the resource schema, such as a
    /// resource that omits a required attribute.
    pub(crate) fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self {
            scim_type: "invalidSyntax",
            detail: detail.into(),
        }
    }

    /// The operation names no target, or its value filter matched nothing.
    pub(crate) fn no_target(detail: impl Into<String>) -> Self {
        Self {
            scim_type: "noTarget",
            detail: detail.into(),
        }
    }

    /// The `path` is not one the operation can address.
    pub(crate) fn invalid_path(detail: impl Into<String>) -> Self {
        Self {
            scim_type: "invalidPath",
            detail: detail.into(),
        }
    }

    /// The value filter in a `path` is not one the server supports.
    pub(crate) fn invalid_filter(detail: impl Into<String>) -> Self {
        Self {
            scim_type: "invalidFilter",
            detail: detail.into(),
        }
    }
}

impl IntoResponse for AttributeError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(400, self.detail).with_type(self.scim_type)),
        )
            .into_response()
    }
}

/// A single-valued attribute of a SCIM resource, and how PATCH changes it.
pub(crate) struct Attribute<S> {
    /// Every attribute path addressing this attribute; the first is
    /// canonical and the rest are aliases identity providers send for the
    /// same stored field. Attribute names are case insensitive
    /// (RFC 7643 §2.1).
    pub paths: &'static [&'static str],
    /// Stores the value an `add` or `replace` presents at `path`.
    pub set: fn(&mut S, &str, &serde_json::Value) -> Result<(), AttributeError>,
    /// Clears the stored value for a `remove`, or rejects the removal when
    /// the attribute has no absent state.
    pub remove: fn(&mut S, &str) -> Result<(), AttributeError>,
}

/// The value of a required attribute of a POST or PUT resource body.
///
/// A body that omits one "did not conform to the request schema", RFC 7644
/// §3.12 Table 9's `invalidSyntax`, which lists POST (Create) and PUT.
/// `invalidValue` stays for a value that is present but unusable.
pub(crate) fn required_attribute<'v>(
    name: &str,
    value: Option<&'v str>,
) -> Result<&'v str, AttributeError> {
    value.ok_or_else(|| AttributeError::invalid_syntax(format!("{name} is required")))
}

/// A PATCH operation and its value, in the shape RFC 7644 §3.5.2 gives it.
///
/// An `add` "MUST contain a "value" member" (§3.5.2.1) and a `replace`
/// writes the value it carries (§3.5.2.3), so both hold one. A `remove` may
/// carry one: Entra names the members to remove in it.
#[derive(Clone, Copy)]
pub(crate) enum PatchOp<'v> {
    Add(&'v serde_json::Value),
    Replace(&'v serde_json::Value),
    Remove(Option<&'v serde_json::Value>),
}

/// A request's PATCH operation after its shape is checked: the only way to
/// obtain a [`PatchOp`] from a request body.
pub(crate) struct PatchOperation<'v> {
    pub path: Option<&'v str>,
    pub op: PatchOp<'v>,
    schema_urn: &'static str,
}

impl<'v> PatchOperation<'v> {
    /// Checks `operation` against the resource whose core schema is
    /// `schema_urn`.
    ///
    /// A pathless `add` or `replace` targets the resource itself, and RFC 7644
    /// §3.5.2.3: "In this case, the "value" attribute SHALL contain a list of
    /// one or more attributes that are to be replaced." Its value must be an
    /// object naming each attribute once; a name may carry the core schema URN
    /// prefix (§3.10).
    pub(crate) fn parse(
        operation: &'v ScimPatchOp,
        schema_urn: &'static str,
    ) -> Result<Self, AttributeError> {
        let op = match (operation.op, operation.value.as_ref()) {
            (ScimPatchOpType::Add, Some(value)) => PatchOp::Add(value),
            (ScimPatchOpType::Replace, Some(value)) => PatchOp::Replace(value),
            (ScimPatchOpType::Remove, value) => PatchOp::Remove(value),
            (ScimPatchOpType::Add | ScimPatchOpType::Replace, None) => {
                return Err(AttributeError::invalid_value(
                    "add and replace operations require a value",
                ));
            }
        };
        if operation.path.is_none()
            && let PatchOp::Add(value) | PatchOp::Replace(value) = op
        {
            let Some(attributes) = value.as_object().filter(|a| !a.is_empty()) else {
                return Err(AttributeError::invalid_value(
                    "an add or replace without a path requires an object of one or more attributes",
                ));
            };
            let mut names = std::collections::HashSet::new();
            for key in attributes.keys() {
                if !names.insert(unqualified(key, schema_urn).to_ascii_lowercase()) {
                    return Err(AttributeError::invalid_syntax(format!(
                        "{key} names an attribute the value already presents"
                    )));
                }
            }
        }
        Ok(Self {
            path: operation.path.as_deref(),
            op,
            schema_urn,
        })
    }

    /// The same operation applied to attribute `name` of a pathless `add` or
    /// `replace` value object, if the object presents it.
    pub(crate) fn attribute(&self, name: &str) -> Option<PatchOp<'v>> {
        match self.op {
            PatchOp::Add(value) => {
                get_top_level_attribute(value, self.schema_urn, name).map(PatchOp::Add)
            }
            PatchOp::Replace(value) => {
                get_top_level_attribute(value, self.schema_urn, name).map(PatchOp::Replace)
            }
            PatchOp::Remove(_) => None,
        }
    }
}

/// Looks up `name` in a JSON object case-insensitively, as RFC 7643 §2.1
/// makes attribute names.
pub(crate) fn get_attribute<'v>(
    value: &'v serde_json::Value,
    name: &str,
) -> Option<&'v serde_json::Value> {
    value
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

/// Looks up top-level attribute `name` in a value object, accepting a key
/// that carries the core schema URN prefix (RFC 7644 §3.10: "Clients MAY
/// omit core schema attribute URN prefixes").
fn get_top_level_attribute<'v>(
    value: &'v serde_json::Value,
    schema_urn: &str,
    name: &str,
) -> Option<&'v serde_json::Value> {
    value
        .as_object()?
        .iter()
        .find(|(key, _)| unqualified(key, schema_urn).eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

/// Strips `prefix` from the start of `s`, comparing ASCII case-insensitively.
pub(crate) fn strip_prefix_ignore_ascii_case<'s>(s: &'s str, prefix: &str) -> Option<&'s str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| s.get(prefix.len()..))
        .flatten()
}

/// The attribute path with the resource's core schema URN prefix removed.
///
/// RFC 7644 §3.10: "Clients MAY omit core schema attribute URN prefixes",
/// so `urn:ietf:params:scim:schemas:core:2.0:User:userName` and `userName`
/// address the same attribute, and "All facets (URN, attribute, and
/// sub-attribute name) of the fully encoded attribute name are case
/// insensitive." Paths under any other URN (schema extensions) are returned
/// unchanged.
pub(crate) fn unqualified<'p>(path: &'p str, schema_urn: &str) -> &'p str {
    path.get(..schema_urn.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(schema_urn))
        .and_then(|_| path.get(schema_urn.len()..))
        .and_then(|rest| rest.strip_prefix(':'))
        .unwrap_or(path)
}

/// Applies one PATCH operation to `state` using `table`, the attributes of
/// the resource whose core schema is `schema_urn`.
pub(crate) fn apply_patch_op<S>(
    table: &[Attribute<S>],
    schema_urn: &str,
    state: &mut S,
    operation: &PatchOperation<'_>,
) -> Result<(), AttributeError> {
    let Some(path) = operation.path.map(|path| unqualified(path, schema_urn)) else {
        return match operation.op {
            PatchOp::Add(value) | PatchOp::Replace(value) => merge(table, schema_urn, state, value),
            PatchOp::Remove(_) => Err(AttributeError::no_target(
                "remove operations require a path",
            )),
        };
    };

    let Some(attribute) = table
        .iter()
        .find(|attribute| attribute.paths.iter().any(|p| p.eq_ignore_ascii_case(path)))
    else {
        return Ok(());
    };

    match operation.op {
        PatchOp::Add(value) | PatchOp::Replace(value) => (attribute.set)(state, path, value),
        PatchOp::Remove(_) => (attribute.remove)(state, path),
    }
}

/// Merges the value object of an operation with no `path`: every attribute
/// the object presents is stored, addressed by its dotted path.
///
/// An attribute reachable under several paths takes the first one the object
/// presents, in table order, so the canonical path wins over its aliases. A
/// bulk object carrying both `name.formatted` and `displayName` — including
/// one holding `null` to clear the attribute the other sets — would otherwise
/// resolve by table position rather than by which name the attribute is
/// actually stored under.
fn merge<S>(
    table: &[Attribute<S>],
    schema_urn: &str,
    state: &mut S,
    value: &serde_json::Value,
) -> Result<(), AttributeError> {
    for attribute in table {
        for path in attribute.paths {
            let mut segments = path.split('.');
            let presented = segments
                .next()
                .and_then(|first| get_top_level_attribute(value, schema_urn, first))
                .and_then(|top| {
                    segments.try_fold(top, |current, segment| get_attribute(current, segment))
                });
            if let Some(presented) = presented {
                (attribute.set)(state, path, presented)?;
                break;
            }
        }
    }
    Ok(())
}

/// Reads the value of an optional string attribute: a JSON string stores it
/// and JSON `null` clears it — identity providers send `null` to unset an
/// attribute — while any other JSON type is not a value the attribute can
/// hold.
pub(crate) fn optional_string(
    path: &str,
    value: &serde_json::Value,
) -> Result<Option<String>, AttributeError> {
    match value {
        serde_json::Value::String(s) => Ok(Some(s.clone())),
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => Err(AttributeError::invalid_value(format!(
            "{path} must be a string"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, PartialEq, Eq, Debug)]
    struct Resource {
        label: Option<String>,
        enabled: bool,
    }

    const RESOURCE_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

    const ATTRIBUTES: &[Attribute<Resource>] = &[
        Attribute {
            paths: &["name.formatted", "displayName"],
            set: |resource, path, value| {
                resource.label = optional_string(path, value)?;
                Ok(())
            },
            remove: |resource, _| {
                resource.label = None;
                Ok(())
            },
        },
        Attribute {
            paths: &["enabled"],
            set: |resource, path, value| {
                let Some(enabled) = value.as_bool() else {
                    return Err(AttributeError::invalid_value(format!(
                        "{path} must be a boolean"
                    )));
                };
                resource.enabled = enabled;
                Ok(())
            },
            remove: |_, path| {
                Err(AttributeError::invalid_value(format!(
                    "{path} cannot be removed"
                )))
            },
        },
    ];

    fn patch_op(
        op: ScimPatchOpType,
        path: Option<&str>,
        value: Option<serde_json::Value>,
    ) -> ScimPatchOp {
        ScimPatchOp {
            op,
            path: path.map(String::from),
            value,
        }
    }

    fn apply(operation: &ScimPatchOp) -> Result<Resource, AttributeError> {
        let mut resource = Resource::default();
        apply_patch_op(
            ATTRIBUTES,
            RESOURCE_URN,
            &mut resource,
            &PatchOperation::parse(operation, RESOURCE_URN)?,
        )?;
        Ok(resource)
    }

    #[test]
    fn add_and_replace_store_the_same_value() {
        let value = Some(serde_json::json!("Ada"));
        let added = apply(&patch_op(
            ScimPatchOpType::Add,
            Some("displayName"),
            value.clone(),
        ))
        .ok();
        let replaced = apply(&patch_op(
            ScimPatchOpType::Replace,
            Some("displayName"),
            value,
        ))
        .ok();

        assert_eq!(added, replaced);
        assert_eq!(
            replaced,
            Some(Resource {
                label: Some("Ada".to_string()),
                enabled: false,
            })
        );
    }

    #[test]
    fn an_alias_addresses_the_same_attribute() {
        let value = Some(serde_json::json!("Ada"));
        let canonical = apply(&patch_op(
            ScimPatchOpType::Replace,
            Some("name.formatted"),
            value.clone(),
        ))
        .ok();
        let alias = apply(&patch_op(
            ScimPatchOpType::Replace,
            Some("DISPLAYNAME"),
            value,
        ))
        .ok();

        assert_eq!(canonical, alias);
    }

    #[test]
    fn remove_clears_a_removable_attribute_and_rejects_the_rest() {
        let mut resource = Resource {
            label: Some("Ada".to_string()),
            enabled: true,
        };
        let cleared = apply_patch_op(
            ATTRIBUTES,
            RESOURCE_URN,
            &mut resource,
            &PatchOperation {
                path: Some("displayName"),
                op: PatchOp::Remove(None),
                schema_urn: RESOURCE_URN,
            },
        );
        assert!(cleared.is_ok());
        assert_eq!(resource.label, None);

        let rejected = apply_patch_op(
            ATTRIBUTES,
            RESOURCE_URN,
            &mut resource,
            &PatchOperation {
                path: Some("enabled"),
                op: PatchOp::Remove(None),
                schema_urn: RESOURCE_URN,
            },
        );
        assert!(rejected.is_err(), "a non-removable attribute must reject");
        assert!(resource.enabled, "a rejected removal must change nothing");
    }

    #[test]
    fn an_unclaimed_path_is_ignored_by_every_operation() {
        for operation in [
            ScimPatchOpType::Add,
            ScimPatchOpType::Replace,
            ScimPatchOpType::Remove,
        ] {
            let applied = apply(&patch_op(
                operation,
                Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"),
                Some(serde_json::json!("Sales")),
            ));
            assert_eq!(applied.ok(), Some(Resource::default()));
        }
    }

    #[test]
    fn a_pathless_operation_merges_every_presented_attribute() {
        let applied = apply(&patch_op(
            ScimPatchOpType::Add,
            None,
            Some(serde_json::json!({"name": {"formatted": "Ada"}, "enabled": true})),
        ));

        assert_eq!(
            applied.ok(),
            Some(Resource {
                label: Some("Ada".to_string()),
                enabled: true,
            })
        );
    }

    // RFC 7644 §3.10: "Clients MAY omit core schema attribute URN prefixes",
    // and every facet of the fully encoded name is case insensitive.
    #[test]
    fn a_core_urn_qualified_path_addresses_the_attribute() {
        let applied = apply(&patch_op(
            ScimPatchOpType::Replace,
            Some("URN:ietf:params:scim:schemas:core:2.0:user:DisplayName"),
            Some(serde_json::json!("Ada")),
        ));
        assert_eq!(applied.ok().and_then(|r| r.label), Some("Ada".to_string()));

        let extension = apply(&patch_op(
            ScimPatchOpType::Replace,
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:displayName"),
            Some(serde_json::json!("Ada")),
        ));
        assert_eq!(
            extension.ok(),
            Some(Resource::default()),
            "an extension attribute is not the core attribute of the same name"
        );
    }

    // RFC 7644 §3.5.2.2: "If "path" is unspecified, the operation fails with
    // HTTP status code 400 and a "scimType" error code of "noTarget"."
    #[test]
    fn a_pathless_remove_is_no_target() {
        let removed = apply(&patch_op(ScimPatchOpType::Remove, None, None));
        assert_eq!(removed.err().map(|e| e.scim_type), Some("noTarget"));
    }

    // RFC 7644 §3.5.2.1: "The operation MUST contain a "value" member".
    #[test]
    fn add_or_replace_without_a_value_is_invalid_value() {
        for operation in [ScimPatchOpType::Add, ScimPatchOpType::Replace] {
            for path in [None, Some("displayName")] {
                let applied = apply(&patch_op(operation, path, None));
                assert_eq!(applied.err().map(|e| e.scim_type), Some("invalidValue"));
            }
        }
    }

    // RFC 7643 §2.1: attribute names are case insensitive, including inside
    // a pathless operation's value object.
    #[test]
    fn a_pathless_operation_matches_names_case_insensitively() {
        let applied = apply(&patch_op(
            ScimPatchOpType::Replace,
            None,
            Some(serde_json::json!({"NAME": {"Formatted": "Ada"}, "Enabled": true})),
        ));
        assert_eq!(
            applied.ok(),
            Some(Resource {
                label: Some("Ada".to_string()),
                enabled: true,
            })
        );
    }

    #[test]
    fn a_value_the_attribute_cannot_hold_is_rejected() {
        let wrong_type = apply(&patch_op(
            ScimPatchOpType::Replace,
            Some("enabled"),
            Some(serde_json::json!("true")),
        ));
        assert!(wrong_type.is_err(), "a string is not a boolean");

        let in_bulk = apply(&patch_op(
            ScimPatchOpType::Replace,
            None,
            Some(serde_json::json!({"enabled": "true"})),
        ));
        assert!(in_bulk.is_err(), "a pathless operation is equally strict");
    }
}
