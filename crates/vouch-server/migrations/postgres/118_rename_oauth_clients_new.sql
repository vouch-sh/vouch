-- Rename new table to original name (one DDL per migration for DSQL).
ALTER TABLE oauth_clients_new RENAME TO oauth_clients;
