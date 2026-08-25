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
/// Returns the schema definitions for supported resource types (RFC 7643
/// Section 7). Both the `Resources` array and the list counts are derived
/// from `urn::RESOURCE_SCHEMAS`, so `totalResults` cannot disagree with the
/// number of returned schemas and adding a resource is one edit.
pub(crate) async fn schemas() -> impl IntoResponse {
    let resources: Vec<ScimSchema> = urn::RESOURCE_SCHEMAS
        .iter()
        .map(|r| ScimSchema {
            id: r.id.to_string(),
            name: r.name.to_string(),
            description: r.description.to_string(),
            attributes: r
                .attributes
                .iter()
                .map(|a| ScimAttribute {
                    name: a.name.to_string(),
                    attr_type: a.attr_type.to_string(),
                    multi_valued: a.multi_valued,
                    required: a.required,
                    case_exact: a.case_exact,
                    mutability: a.mutability.to_string(),
                    returned: a.returned.to_string(),
                    uniqueness: a.uniqueness.to_string(),
                })
                .collect(),
        })
        .collect();
    let count = resources.len();

    Json(ScimListResponse {
        schemas: vec![urn::LIST_RESPONSE.to_string()],
        total_results: count,
        items_per_page: count,
        start_index: 1,
        resources,
    })
}

/// GET /scim/v2/ResourceTypes (RFC 7644 Section 4).
///
/// Returns the Resource Type definitions (RFC 7643 Section 6). Both the
/// `Resources` array and the list counts are derived from
/// `urn::RESOURCE_SCHEMAS`, so `totalResults` cannot disagree with the
/// number of returned resource types and adding a resource is one edit.
pub(crate) async fn resource_types(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base_url = &state.config().base_url;

    let resources: Vec<ScimResourceType> = urn::RESOURCE_SCHEMAS
        .iter()
        .map(|r| ScimResourceType {
            schemas: vec![urn::RESOURCE_TYPE.to_string()],
            id: r.name.to_string(),
            name: r.name.to_string(),
            endpoint: format!("{base_url}/scim/v2{}", r.endpoint),
            description: r.description.to_string(),
            schema: r.id.to_string(),
        })
        .collect();
    let count = resources.len();

    Json(ScimListResponse {
        schemas: vec![urn::LIST_RESPONSE.to_string()],
        total_results: count,
        items_per_page: count,
        start_index: 1,
        resources,
    })
}
