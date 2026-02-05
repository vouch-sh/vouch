// SPDX-License-Identifier: BUSL-1.1
//! SCIM 2.0 discovery endpoints (RFC 7644 Section 4).

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::types::{
    ScimAttribute, ScimAuthScheme, ScimBulkConfig, ScimFilterConfig, ScimListResponse,
    ScimResourceType, ScimSchema, ScimServiceProviderConfig, ScimSupported,
};
use crate::AppState;

/// GET /scim/v2/ServiceProviderConfig
pub async fn service_provider_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = &state.config().base_url;

    Json(ScimServiceProviderConfig {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_string()],
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

/// GET /scim/v2/Schemas
pub async fn schemas() -> impl IntoResponse {
    let user_schema = ScimSchema {
        id: "urn:ietf:params:scim:schemas:core:2.0:User".to_string(),
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
        id: "urn:ietf:params:scim:schemas:core:2.0:Group".to_string(),
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
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 2,
        items_per_page: 2,
        start_index: 1,
        resources: vec![user_schema, group_schema],
    })
}

/// GET /scim/v2/ResourceTypes
pub async fn resource_types(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = &state.config().base_url;

    Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 2,
        items_per_page: 2,
        start_index: 1,
        resources: vec![
            ScimResourceType {
                schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ResourceType".to_string()],
                id: "User".to_string(),
                name: "User".to_string(),
                endpoint: format!("{base_url}/scim/v2/Users"),
                description: "User Account".to_string(),
                schema: "urn:ietf:params:scim:schemas:core:2.0:User".to_string(),
            },
            ScimResourceType {
                schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ResourceType".to_string()],
                id: "Group".to_string(),
                name: "Group".to_string(),
                endpoint: format!("{base_url}/scim/v2/Groups"),
                description: "Group".to_string(),
                schema: "urn:ietf:params:scim:schemas:core:2.0:Group".to_string(),
            },
        ],
    })
}
