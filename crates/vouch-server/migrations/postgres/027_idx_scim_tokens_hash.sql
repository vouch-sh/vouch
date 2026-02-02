-- Index for SCIM token hash lookups
CREATE INDEX ASYNC idx_scim_tokens_hash ON scim_tokens(token_hash);
