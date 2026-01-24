-- Add AAGUID column to authenticators table
-- AAGUID is a 16-byte UUID that identifies the authenticator model
ALTER TABLE authenticators ADD COLUMN aaguid TEXT;
