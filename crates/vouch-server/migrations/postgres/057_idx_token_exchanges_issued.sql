-- Index for token exchange lookups by issued token hash
CREATE INDEX ASYNC idx_token_exchanges_issued ON token_exchanges(issued_token_hash);
