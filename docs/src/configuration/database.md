# Database Setup

Vouch supports three database backends.

## SQLite (Default)

Best for single-node deployments and development. No external dependencies.

```bash
VOUCH_DATABASE_URL=sqlite:vouch.db?mode=rwc
```

The database file is created automatically on first startup. Migrations run automatically.

**Recommendations:**
- Store the database on a persistent volume
- Set restrictive file permissions: `chmod 700 /data`
- Back up the file regularly (it's a single file)

```bash
# Create data directory
mkdir -p /data
chmod 700 /data

# Configure
export VOUCH_DATABASE_URL="sqlite:/data/vouch.db?mode=rwc"
```

## PostgreSQL

Best for multi-node deployments, high availability, and production environments.

```bash
VOUCH_DATABASE_URL=postgres://user:password@db.example.com:5432/vouch
```

**Setup:**

1. Create a PostgreSQL database:
   ```sql
   CREATE DATABASE vouch;
   CREATE USER vouch WITH PASSWORD 'secure-password';
   GRANT ALL PRIVILEGES ON DATABASE vouch TO vouch;
   ```

2. Configure the connection:
   ```bash
   export VOUCH_DATABASE_URL="postgres://vouch:secure-password@db.example.com:5432/vouch"
   ```

3. Migrations run automatically on server startup.

**Recommendations:**
- Use SSL for database connections in production
- Configure connection pooling at the database level
- Set up automated backups

## Aurora DSQL

For AWS deployments requiring serverless, distributed SQL with strong consistency.

Aurora DSQL endpoints are auto-detected when the `DATABASE_URL` hostname contains `.dsql.` and ends with `.on.aws`. IAM authentication tokens are generated automatically.

```bash
VOUCH_DATABASE_URL=postgres://admin@abcdef123456.dsql.us-east-1.on.aws:5432/vouch
```

**Multi-region configuration** uses a `dsql_endpoints` map in the S3 configuration JSON, resolved via `AWS_AZ` or `AWS_REGION` environment variables.

## Migrations

Database migrations are embedded in the server binary and run automatically on startup. There is no manual migration step required.

- SQLite migrations: `crates/vouch-server/migrations/sqlite/`
- PostgreSQL migrations: `crates/vouch-server/migrations/postgres/`

### Index builds on Aurora DSQL

DSQL builds every index asynchronously: `CREATE INDEX ASYNC` returns a job ID as
soon as the build is submitted, so startup finishes before the index is usable.
Until the build completes the index is marked invalid and the planner ignores
it. Migrations that replace an index therefore leave a window — after the old
index is dropped and before the new one is valid — in which the affected query
falls back to a scan. The queries involved so far belong to the background
expiry sweep, so the effect is a slower sweep, not a slower request.

Watch a build from a `psql` session against the cluster:

```sql
SELECT job_id, status, object_name FROM sys.jobs WHERE job_type = 'INDEX_BUILD';
```

A `failed` job leaves the index definition in place but invalid, and DSQL does
not remove it. The migration is already recorded in `_sqlx_migrations`, so a
restart will not retry it — drop the index by name and re-issue the statement
from the matching file in `migrations/postgres/` by hand.

## Backup

| Database | Backup Method | Frequency |
|----------|--------------|-----------|
| SQLite | File copy (`cp vouch.db vouch.db.backup`) | Daily |
| PostgreSQL | `pg_dump` | Daily |
| Aurora DSQL | AWS automated backups | Continuous |

Back up before upgrading the Vouch server: migrations modify the schema, and restoring a backup is the only rollback.
