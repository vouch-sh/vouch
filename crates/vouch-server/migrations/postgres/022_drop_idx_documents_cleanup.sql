-- Superseded by idx_documents_cleanup_unexpired (020).
--
-- `CREATE INDEX ASYNC` returns as soon as the build job is submitted, so the
-- replacement may still be building when this runs; DSQL marks it valid only
-- once the job completes. The gap costs `delete_expired` a scan on the next
-- sweep, not correctness, and the background sweep is the only reader.
DROP INDEX IF EXISTS idx_documents_cleanup;
