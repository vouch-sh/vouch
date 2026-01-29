-- Add repositories column to github_installations
-- Stores JSON array of repository names when repository_selection is "selected"
ALTER TABLE github_installations ADD COLUMN repositories TEXT;
