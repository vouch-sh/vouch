-- FAPI 2.0: Apply NOT NULL constraint after populating defaults
ALTER TABLE oauth_clients ALTER COLUMN fapi_profile SET NOT NULL;
