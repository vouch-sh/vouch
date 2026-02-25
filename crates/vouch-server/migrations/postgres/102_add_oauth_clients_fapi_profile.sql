-- FAPI 2.0: Add fapi_profile column to oauth_clients
ALTER TABLE oauth_clients ADD COLUMN fapi_profile TEXT;
