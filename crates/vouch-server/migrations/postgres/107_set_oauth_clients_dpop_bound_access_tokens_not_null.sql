-- FAPI 2.0: Apply NOT NULL constraint after populating defaults
ALTER TABLE oauth_clients ALTER COLUMN dpop_bound_access_tokens SET NOT NULL;
