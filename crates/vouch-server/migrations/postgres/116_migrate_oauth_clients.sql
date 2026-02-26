-- Copy data from old table to new table with constraint changes.
-- COALESCE guards against NULLs for newly NOT NULL columns.
INSERT INTO oauth_clients_new (
    id, user_id, client_id, name, description,
    application_type, redirect_uris, active,
    created_at, updated_at, last_used_at,
    access_scope, org_id, resource_uris,
    jwks, jwks_uri, jwks_uri_cached_at, jwks_uri_cache,
    token_endpoint_auth_method,
    request_object_signing_alg, require_signed_request_object,
    fapi_profile, dpop_bound_access_tokens,
    grant_types, response_types,
    software_id, software_version,
    registration_source, registration_access_token_hash,
    registration_metadata
)
SELECT
    id, user_id, client_id, name, description,
    application_type, redirect_uris, active,
    created_at, updated_at, last_used_at,
    access_scope, org_id, resource_uris,
    jwks, jwks_uri, jwks_uri_cached_at, jwks_uri_cache,
    token_endpoint_auth_method,
    request_object_signing_alg, require_signed_request_object,
    COALESCE(fapi_profile, 'none'),
    COALESCE(dpop_bound_access_tokens, false),
    grant_types, response_types,
    software_id, software_version,
    registration_source, registration_access_token_hash,
    registration_metadata
FROM oauth_clients;
