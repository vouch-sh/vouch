// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SCIM 2.0 discovery endpoints (RFC 7644 Section 4).

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::types::{
    ScimAttribute, ScimAuthScheme, ScimBulkConfig, ScimFilterConfig, ScimListResponse,
    ScimResourceType, ScimSchema, ScimServiceProviderConfig, ScimSupported,
};
use super::urn;
use crate::AppState;

/// GET /scim/v2/ServiceProviderConfig (RFC 7644 Section 4).
///
/// Returns the Service Provider's configuration (RFC 7643 Section 5),
/// describing supported SCIM capabilities: patch, bulk, filter, etc.
pub(crate) async fn service_provider_config(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let base_url = &state.config().base_url;

    Json(ScimServiceProviderConfig {
        schemas: vec![urn::SERVICE_PROVIDER_CONFIG.to_string()],
        documentation_uri: format!("{base_url}/docs/scim"),
        patch: ScimSupported { supported: true },
        bulk: ScimBulkConfig {
            supported: false,
            max_operations: 0,
            max_payload_size: 0,
        },
        filter: ScimFilterConfig {
            supported: true,
            max_results: 100,
        },
        change_password: ScimSupported { supported: false },
        sort: ScimSupported { supported: false },
        etag: ScimSupported { supported: false },
        authentication_schemes: vec![ScimAuthScheme {
            name: "OAuth Bearer Token".to_string(),
            description: "Authentication scheme using the OAuth Bearer Token Standard".to_string(),
            auth_type: "oauthbearertoken".to_string(),
            spec_uri: "https://tools.ietf.org/html/rfc6750".to_string(),
        }],
    })
}

/// GET /scim/v2/Schemas (RFC 7644 Section 4).
///
/// Returns the schema definitions for supported resource types (RFC 7643 Section 7).
pub(crate) async fn schemas() -> impl IntoResponse {
    let user_schema = ScimSchema {
        id: urn::USER.to_string(),
        name: "User".to_string(),
        description: "User Account".to_string(),
        attributes: vec![
            ScimAttribute {
                name: "userName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                required: true,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "server".to_string(),
            },
            ScimAttribute {
                name: "name".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: false,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
            ScimAttribute {
                name: "emails".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
            ScimAttribute {
                name: "active".to_string(),
                attr_type: "boolean".to_string(),
                multi_valued: false,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
        ],
    };

    let group_schema = ScimSchema {
        id: urn::GROUP.to_string(),
        name: "Group".to_string(),
        description: "Group".to_string(),
        attributes: vec![
            ScimAttribute {
                name: "displayName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                required: true,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "server".to_string(),
            },
            ScimAttribute {
                name: "members".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
            },
        ],
    };

    Json(ScimListResponse {
        schemas: vec![urn::LIST_RESPONSE.to_string()],
        total_results: urn::RESOURCE_SCHEMAS.len(),
        items_per_page: urn::RESOURCE_SCHEMAS.len(),
        start_index: 1,
        resources: vec![user_schema, group_schema],
    })
}

/// GET /scim/v2/ResourceTypes (RFC 7644 Section 4).
///
/// Returns the Resource Type definitions (RFC 7643 Section 6).
pub(crate) async fn resource_types(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = &state.config().base_url;

    Json(ScimListResponse {
        schemas: vec![urn::LIST_RESPONSE.to_string()],
        total_results: 2,
        items_per_page: 2,
        start_index: 1,
        // Derived from `urn::RESOURCE_SCHEMAS` so an advertised resource type
        // and the schema its handler emits cannot be edited apart.
        resources: urn::RESOURCE_SCHEMAS
            .iter()
            .map(|(schema, endpoint)| {
                let name = endpoint.trim_start_matches('/').trim_end_matches('s');
                ScimResourceType {
                    schemas: vec![urn::RESOURCE_TYPE.to_string()],
                    id: name.to_string(),
                    name: name.to_string(),
                    endpoint: format!("{base_url}/scim/v2{endpoint}"),
                    description: name.to_string(),
                    schema: (*schema).to_string(),
                }
            })
            .collect(),
    })
}
