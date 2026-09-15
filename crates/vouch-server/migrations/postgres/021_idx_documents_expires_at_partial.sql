-- Partial replacement for idx_documents_expires_at, matching the predicate
-- the SQLite schema has carried since 001_initial.sql:
--   CREATE INDEX ... ON documents(expires_at) WHERE expires_at IS NOT NULL
-- Postgres/DSQL only lacked it because DSQL rejected partial indexes at the
-- time these migrations were written.
CREATE INDEX ASYNC idx_documents_expires_at_unexpired ON documents(expires_at) WHERE expires_at IS NOT NULL;
