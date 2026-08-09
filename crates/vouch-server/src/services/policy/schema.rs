// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Dogwood schema construction: the service schema (defaults) and the Vouch
//! action schema, both built once and cached for the process lifetime.
//!
//! Fail-closed: if the embedded `.cedarschema` fails to parse,
//! [`policy_schema`] returns `None` and every policy evaluation reports the
//! engine unavailable rather than silently passing.

use dogwood_language::{PolicySchema, ServiceSchema};
use std::sync::LazyLock;

/// The embedded Vouch action schema (entities, actions, the Posture record).
pub(crate) const VOUCH_CEDARSCHEMA: &str = include_str!("vouch.cedarschema");

static SERVICE_SCHEMA: LazyLock<ServiceSchema> = LazyLock::new(ServiceSchema::defaults);

static POLICY_SCHEMA: LazyLock<Option<PolicySchema>> =
    LazyLock::new(
        || match PolicySchema::from_cedarschema_str(VOUCH_CEDARSCHEMA) {
            Ok(schema) => Some(schema),
            Err(e) => {
                tracing::error!("embedded vouch.cedarschema failed to parse: {e:?}");
                None
            }
        },
    );

/// The service-provided schema half (default event schema with the
/// `callerPrincipal` pin, default temporal macro library, no providers).
pub(crate) fn service_schema() -> &'static ServiceSchema {
    &SERVICE_SCHEMA
}

/// The Vouch action schema, or `None` if the embedded schema is invalid
/// (callers must treat `None` as a deny).
pub(crate) fn policy_schema() -> Option<&'static PolicySchema> {
    POLICY_SCHEMA.as_ref()
}
