-- RFC 8707: Populate existing rows with empty JSON array.
UPDATE oauth_clients SET resource_uris = '[]' WHERE resource_uris IS NULL;
