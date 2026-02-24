-- FAPI 2.0: Populate dpop_bound_access_tokens default for existing rows
UPDATE oauth_clients SET dpop_bound_access_tokens = false WHERE dpop_bound_access_tokens IS NULL;
