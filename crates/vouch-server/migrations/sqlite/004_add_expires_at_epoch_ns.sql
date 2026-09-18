-- Add a nanosecond-precision epoch column mirroring `expires_at`, used by the
-- expiry comparison predicates (consume-once and background sweep).
--
-- `expires_at` is a minimal-fraction RFC 3339 TEXT column; comparing it with
-- SQL `<`/`>` mis-sorts two instants that share an integer-second field when
-- one minimal fraction is a strict prefix of the other (e.g. `.5Z` sorts
-- after `.5001Z` lexically, opposite to chronology). The integer
-- `expires_at_epoch_ns` column makes the comparison a lossless chronological
-- integer compare at `Timestamp` precision. Backfilled in the next migration.

ALTER TABLE documents ADD COLUMN expires_at_epoch_ns BIGINT;
