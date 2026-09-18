-- Backfill `expires_at_epoch_ns` from the existing `expires_at` TEXT column
-- for rows written before the epoch column existed.
--
-- Casts each RFC 3339 string to `timestamptz` (microsecond precision — jiff
-- writes nanoseconds, the cast rounds to micros), extracts epoch seconds, and
-- scales to nanoseconds. The integer compare is monotonic so no lexical flip
-- survives; the cast's sub-microsecond rounding shifts legacy rows by <1 µs,
-- far inside the ~300 s single-use nonce lifetime.
--
-- Idempotent: `expires_at_epoch_ns IS NULL` skips rows already backfilled, so
-- a re-run on migration-record recovery re-applies cleanly.

UPDATE documents
SET expires_at_epoch_ns = (EXTRACT(EPOCH FROM expires_at::timestamptz) * 1000000000)::bigint
WHERE expires_at IS NOT NULL
  AND expires_at_epoch_ns IS NULL;
