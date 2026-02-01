-- Index for token exchange lookups by subject user
CREATE INDEX ASYNC idx_token_exchanges_subject ON token_exchanges(subject_user_id);
