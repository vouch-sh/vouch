-- FAPI 2.0: Add dpop_jkt column to pushed_authorization_requests for DPoP code binding
ALTER TABLE pushed_authorization_requests ADD COLUMN dpop_jkt TEXT;
