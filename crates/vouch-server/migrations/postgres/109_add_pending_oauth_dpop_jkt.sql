-- FAPI 2.0: Add dpop_jkt column to pending_oauth_authorizations for DPoP code binding
ALTER TABLE pending_oauth_authorizations ADD COLUMN dpop_jkt TEXT;
