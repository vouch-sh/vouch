-- Backfill `expires_at_epoch_ns` from the existing `expires_at` TEXT column
-- for rows written before the epoch column existed.
--
-- Converts each RFC 3339 string to nanoseconds-since-epoch via `julianday`
-- (the Unix epoch is Julian day 2440587.5). `CAST(... AS INTEGER)` truncates
-- toward zero, matching jiff's `Timestamp::as_nanosecond` flooring for the
-- reachable positive range. The double-precision product is exact to ~tens
-- of microseconds at present-day magnitudes — far inside the ~300 s single-use
-- nonce lifetime, and the integer compare is monotonic so no lexical flip
-- survives (legacy rows only live ~300 s past deploy anyway).
--
-- Idempotent: `expires_at_epoch_ns IS NULL` skips rows already backfilled, so
-- a re-run on migration-record recovery re-applies cleanly.

UPDATE documents
SET expires_at_epoch_ns = CAST((julianday(expires_at) - 2440587.5) * 86400000000000 AS INTEGER)
WHERE expires_at IS NOT NULL
  AND expires_at_epoch_ns IS NULL;
