-- FAPI 2.0 Security Profile support
ALTER TABLE oauth_clients ADD COLUMN fapi_profile TEXT NOT NULL DEFAULT 'none';
ALTER TABLE oauth_clients ADD COLUMN dpop_bound_access_tokens BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE pushed_authorization_requests ADD COLUMN dpop_jkt TEXT;
ALTER TABLE pending_oauth_authorizations ADD COLUMN dpop_jkt TEXT;
