// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 schema URNs.
//!
//! Discovery advertises these (`/scim/v2/Schemas`, `/ResourceTypes`,
//! `/ServiceProviderConfig`) and the user and group handlers emit them on
//! every resource. Both sides read the constants below, so an advertised URN
//! and an emitted one cannot drift apart by editing only one of them.

/// `urn:ietf:params:scim:schemas:core:2.0:User` — RFC 7643 Section 4.1.
pub(crate) const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// `urn:ietf:params:scim:schemas:core:2.0:Group` — RFC 7643 Section 4.2.
pub(crate) const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// `urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig` — RFC 7643
/// Section 5.
pub(crate) const SERVICE_PROVIDER_CONFIG: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

/// `urn:ietf:params:scim:schemas:core:2.0:ResourceType` — RFC 7643 Section 6.
pub(crate) const RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

/// `urn:ietf:params:scim:api:messages:2.0:ListResponse` — RFC 7644
/// Section 3.4.2.
pub(crate) const LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// `urn:ietf:params:scim:api:messages:2.0:Error` — RFC 7644 Section 3.12.
pub(crate) const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// The resource schemas this server serves, paired with the endpoint that
/// serves each.
///
/// Discovery derives `/ResourceTypes` from this table, and the guard in
/// `tests::protocol` checks the handlers emit the same set, so adding a
/// resource requires touching one place rather than three.
pub(crate) const RESOURCE_SCHEMAS: &[(&str, &str)] = &[(USER, "/Users"), (GROUP, "/Groups")];
