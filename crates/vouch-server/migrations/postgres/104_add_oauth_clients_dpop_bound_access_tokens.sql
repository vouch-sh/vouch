-- FAPI 2.0: Add dpop_bound_access_tokens column to oauth_clients
ALTER TABLE oauth_clients ADD COLUMN dpop_bound_access_tokens BOOLEAN;
