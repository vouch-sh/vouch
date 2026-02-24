-- RFC 7523: Populate existing rows with default auth method.
UPDATE oauth_clients SET token_endpoint_auth_method = 'client_secret_basic' WHERE token_endpoint_auth_method IS NULL;
