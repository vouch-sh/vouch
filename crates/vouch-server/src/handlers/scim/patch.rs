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
//! - `remove` clears the stored value (§3.5.2.2). An attribute with no
//!   absent state — a required or non-nullable one — rejects the removal as
//!   `invalidValue` (§3.12) instead.
//! - An operation with no `path` merges every attribute its value object
//!   presents, each addressed by its dotted path (`name.formatted` reads
//!   `{"name": {"formatted": …}}`).
//! - A path no entry claims is ignored and the request still succeeds.
//!   Identity providers PATCH attributes Vouch does not store — `title`,
//!   `department`, `name.givenName`, enterprise-extension URNs — and
//!   rejecting those fails the whole provisioning sync at the IdP over an
//!   attribute the directory was never going to persist. A pathless
//!   `remove` names no attribute to clear and is likewise ignored.
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

/// A value a PATCH operation cannot store, reported as a SCIM 400
/// `invalidValue` (RFC 7644 §3.12).
pub(crate) struct InvalidValue(String);

impl InvalidValue {
    pub(crate) fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

impl IntoResponse for InvalidValue {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(ScimError::new(400, self.0).with_type("invalidValue")),
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
    pub set: fn(&mut S, &str, &serde_json::Value) -> Result<(), InvalidValue>,
    /// Clears the stored value for a `remove`, or rejects the removal when
    /// the attribute has no absent state.
    pub remove: fn(&mut S, &str) -> Result<(), InvalidValue>,
}

/// Applies one PATCH operation to `state` using `table`.
pub(crate) fn apply_patch_op<S>(
    table: &[Attribute<S>],
    state: &mut S,
    op: &ScimPatchOp,
) -> Result<(), InvalidValue> {
    let Some(path) = op.path.as_deref() else {
        return match op.op {
            ScimPatchOpType::Add | ScimPatchOpType::Replace => match &op.value {
                Some(value) => merge(table, state, value),
                None => Ok(()),
            },
            ScimPatchOpType::Remove => Ok(()),
        };
    };

    let Some(attribute) = table
        .iter()
        .find(|attribute| attribute.paths.iter().any(|p| p.eq_ignore_ascii_case(path)))
    else {
        return Ok(());
    };

    match op.op {
        ScimPatchOpType::Add | ScimPatchOpType::Replace => match &op.value {
            Some(value) => (attribute.set)(state, path, value),
            None => Ok(()),
        },
        ScimPatchOpType::Remove => (attribute.remove)(state, path),
    }
}

/// Merges the value object of an operation with no `path`: every attribute
/// the object presents is stored, addressed by its dotted path.
fn merge<S>(
    table: &[Attribute<S>],
    state: &mut S,
    value: &serde_json::Value,
) -> Result<(), InvalidValue> {
    for attribute in table {
        for path in attribute.paths {
            let presented = path
                .split('.')
                .try_fold(value, |current, segment| current.get(segment));
            if let Some(presented) = presented {
                (attribute.set)(state, path, presented)?;
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
) -> Result<Option<String>, InvalidValue> {
    match value {
        serde_json::Value::String(s) => Ok(Some(s.clone())),
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => {
            Err(InvalidValue::new(format!("{path} must be a string")))
        }
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
                    return Err(InvalidValue::new(format!("{path} must be a boolean")));
                };
                resource.enabled = enabled;
                Ok(())
            },
            remove: |_, path| Err(InvalidValue::new(format!("{path} cannot be removed"))),
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

    fn apply(operation: &ScimPatchOp) -> Result<Resource, InvalidValue> {
        let mut resource = Resource::default();
        apply_patch_op(ATTRIBUTES, &mut resource, operation)?;
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
            &mut resource,
            &patch_op(ScimPatchOpType::Remove, Some("displayName"), None),
        );
        assert!(cleared.is_ok());
        assert_eq!(resource.label, None);

        let rejected = apply_patch_op(
            ATTRIBUTES,
            &mut resource,
            &patch_op(ScimPatchOpType::Remove, Some("enabled"), None),
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
