CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT,
    email_domain TEXT,
    email_hmac TEXT,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
