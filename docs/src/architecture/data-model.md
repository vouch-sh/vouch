# Data Model

This chapter describes the core data entities and their relationships in the Vouch system.

## Core Entities

```
+------------------+       +------------------+
|   Organization   |       |      User        |
+------------------+       +------------------+
| id               |       | id               |
| name             |       | org_id (FK)      |
| domain           |<------| email            |
| settings (JSON)  |       | display_name     |
| created_at       |       | created_at       |
+------------------+       +--------+---------+
                                    |
                                    | 1:N
                                    v
+------------------+       +------------------+
|     Session      |       |   Authenticator  |
+------------------+       |   (FIDO2)        |
| id               |       +------------------+
| user_id (FK)     |       | id               |
| token_hash       |       | user_id (FK)     |
| authenticator_id |       | public_key       |
| expires_at       |       | credential_id    |
| created_at       |       | device_name      |
+------------------+       | counter          |
                           | created_at       |
                           +------------------+
```
