-- FAPI 2.0: Populate fapi_profile default for existing rows
UPDATE oauth_clients SET fapi_profile = 'none' WHERE fapi_profile IS NULL;
