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

/// A schema attribute definition (RFC 7643 Section 7), in static form so the
/// resource-schema table can be a single `const` that both discovery
/// endpoints read from.
pub(crate) struct SchemaAttribute {
    pub name: &'static str,
    pub attr_type: &'static str,
    pub multi_valued: bool,
    pub required: bool,
    pub case_exact: bool,
    pub mutability: &'static str,
    pub returned: &'static str,
    pub uniqueness: &'static str,
}

/// A resource this server serves: its schema URN, the endpoint that serves
/// resources of that schema, and the schema definition `/Schemas` advertises.
///
/// Both `/Schemas` and `/ResourceTypes` derive their list counts and
/// `Resources` arrays from this table, so `totalResults` cannot disagree
/// with the number of returned resources, and adding a resource is one edit
/// (a new entry in [`RESOURCE_SCHEMAS`]) rather than three.
pub(crate) struct ResourceSchema {
    /// The schema URN, e.g. `urn:ietf:params:scim:schemas:core:2.0:User`.
    pub id: &'static str,
    /// The endpoint that serves resources of this schema, e.g. `/Users`.
    pub endpoint: &'static str,
    /// Human-readable name, e.g. `User`.
    pub name: &'static str,
    /// Human-readable description, e.g. `User Account`.
    pub description: &'static str,
    /// Attribute definitions (RFC 7643 Section 7).
    pub attributes: &'static [SchemaAttribute],
}

const USER_ATTRIBUTES: &[SchemaAttribute] = &[
    SchemaAttribute {
        name: "userName",
        attr_type: "string",
        multi_valued: false,
        required: true,
        case_exact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "server",
    },
    SchemaAttribute {
        name: "name",
        attr_type: "complex",
        multi_valued: false,
        required: false,
        case_exact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
    },
    SchemaAttribute {
        name: "emails",
        attr_type: "complex",
        multi_valued: true,
        required: false,
        case_exact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
    },
    SchemaAttribute {
        name: "active",
        attr_type: "boolean",
        multi_valued: false,
        required: false,
        case_exact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
    },
];

const GROUP_ATTRIBUTES: &[SchemaAttribute] = &[
    SchemaAttribute {
        name: "displayName",
        attr_type: "string",
        multi_valued: false,
        required: true,
        case_exact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "server",
    },
    SchemaAttribute {
        name: "members",
        attr_type: "complex",
        multi_valued: true,
        required: false,
        case_exact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
    },
];

/// The resource schemas this server serves, paired with the endpoint that
/// serves each and the schema definition `/Schemas` advertises.
///
/// Both `/Schemas` and `/ResourceTypes` derive their list counts and
/// `Resources` arrays from this table, and the guard in `tests::protocol`
/// checks the handlers emit the same set, so adding a resource requires
/// touching one place rather than three.
pub(crate) const RESOURCE_SCHEMAS: &[ResourceSchema] = &[
    ResourceSchema {
        id: USER,
        endpoint: "/Users",
        name: "User",
        description: "User Account",
        attributes: USER_ATTRIBUTES,
    },
    ResourceSchema {
        id: GROUP,
        endpoint: "/Groups",
        name: "Group",
        description: "Group",
        attributes: GROUP_ATTRIBUTES,
    },
];
