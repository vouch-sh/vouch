# Credential Cache Key Completeness and Cache Bypass

Detects credential cache keys that omit inputs which change the minted credential (region, database, duration, agent source), and detects cacheable credential fetches that bypass `cache::get_or_fetch` and call uncached internals directly.

## What to look for

### 1. Missing inputs in cache keys

A cache key must include **every** input that affects the credential minted. For each credential type:

| Type | Required key components |
|------|------------------------|
| RDS | `hostname`, `port`, `username`, `region`, `role_arn`, `agent` |
| EKS | `cluster_name`, `region`, `role_arn`, `agent` |
| Redshift cluster | `cluster_id`, `db_name`, `duration`, `region`, `role_arn`, `agent` |
| Redshift serverless | `workgroup`, `db_name`, `region`, `role_arn`, `agent` |
| AWS STS | `role_arn`, optional `mgmt_role`, `agent` |

**Region** is a presigning input for RDS and EKS tokens and an STS endpoint selector for all AWS types — omitting it causes cross-region cache collisions.

**Database name and duration** change the Redshift credential minted — omitting either causes one workload's credentials to be returned for a different database or TTL.

**Agent source** (`detect_agent_source()`) changes session policies and IAM tags (issue #426) — omitting it causes agent invocations to reuse non-agent credentials (or vice versa) with different `vouch:AccessType` tags.

### 2. Test-side copies of cache key format

The `cache_key` / `build_cache_key` function must be a single private production function in the module. Tests must call this same function directly, not reimplement the format string. A test-side helper like `build_rds_cache_key` that duplicates the format independently of the production function is a violation — if the production key changes, the test helper drifts silently.

### 3. `exec`/`env`/credential-helper bypassing the cache

Any command path that fetches a cacheable credential (`vouch exec`, `vouch env`, credential helpers) must route through `cache::get_or_fetch`. Calling an uncached internal function (`fetch_redshift_credentials`, `generate_rds_token`, `generate_eks_token`, etc.) directly from `exec.rs` or `env.rs` is a violation. The uncached fetch functions must be `pub(super)` or private to their module so other modules cannot call them.

### 4. Region detection that is not anchored to real AWS endpoints

`extract_region_from_rds_hostname` must validate that the hostname *ends with* the partition-correct RDS DNS suffix (e.g. `.rds.amazonaws.com`, `.rds.cn-north-1.amazonaws.com.cn`) before accepting a label as the region. Searching for any label equal to `"rds"` and returning whatever precedes it is a violation — it fires on custom hostnames like `db.rds.mycompany.com`.

## Violation examples

### Cache key missing region (old `rds.rs` before commit 15800405)

```rust
// VIOLATION: region is absent; two hosts in different regions share a key
let agent_suffix = agent_source
    .as_deref()
    .map_or(String::new(), |src| format!(":agent:{src}"));
let cache_key = format!("rds:{hostname}:{port}:{username}:{role_arn}{agent_suffix}");
```

### Cache key missing db_name and duration (Redshift before commit 15800405)

```rust
// VIOLATION: db_name and duration omitted; wrong credentials returned for different db/TTL
format!("redshift:{cluster_id}:{region}:{role_arn}{agent_suffix}")
```

### Test-side copy of cache key format (old `rds.rs` tests)

```rust
// VIOLATION: duplicates the production format string; drifts silently if production changes
fn build_rds_cache_key(hostname: &str, port: u16, username: &str, role_arn: &str, agent: Option<&str>) -> String {
    let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
    format!("rds:{hostname}:{port}:{username}:{role_arn}{agent_suffix}")
}
```

### exec path calling uncached internal directly (old `exec.rs` before commit c971fa8a)

```rust
// VIOLATION: bypasses cache::get_or_fetch; every exec call makes a full round-trip
let (role_arn, region_name) = aws::resolve_role_and_region(role, opts.region, None)?;
let agent_source = super::credential::aws::detect_agent_source();
super::credential::redshift::fetch_redshift_credentials(
    server, &target, opts.db_name, &region_name, &role_arn, agent_source.as_deref(),
).await
```

### Unanchored RDS region extraction (old `rds.rs` before commit 15800405)

```rust
// VIOLATION: matches any "rds" label; db.rds.mycompany.com -> Some("db")
fn extract_region_from_rds_hostname(hostname: &str) -> Option<&str> {
    let parts: Vec<&str> = hostname.split('.').collect();
    let rds_idx = parts.iter().position(|&p| p == "rds")?;
    let region_idx = rds_idx.checked_sub(1)?;
    parts.get(region_idx).copied()
}
```

## Correct patterns

### Complete RDS cache key (current `rds.rs`)

```rust
fn cache_key(hostname: &str, port: u16, username: &str, region: &str, role_arn: &str, agent: Option<&str>) -> String {
    let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
    format!("rds:{hostname}:{port}:{username}:{region}:{role_arn}{agent_suffix}")
}
```

### Complete Redshift cache key including db_name and duration (current `redshift.rs`)

```rust
fn cache_key(target: &RedshiftTarget<'_>, db_name: Option<&str>, region: &str, role_arn: &str, agent: Option<&str>) -> String {
    let agent_suffix = agent.map_or(String::new(), |src| format!(":agent:{src}"));
    let db = db_name.unwrap_or_default();
    match target {
        RedshiftTarget::Cluster { cluster_id, duration } => {
            let duration = duration.unwrap_or(DEFAULT_DURATION_SECONDS);
            format!("redshift:{cluster_id}:{db}:{duration}:{region}:{role_arn}{agent_suffix}")
        }
        RedshiftTarget::Serverless { workgroup } => {
            format!("redshift-serverless:{workgroup}:{db}:{region}:{role_arn}{agent_suffix}")
        }
    }
}
```

### Tests calling the production function directly (current `rds.rs`)

```rust
// CORRECT: tests call the same cache_key function production code uses
#[test]
fn test_rds_cache_key_format() {
    assert_eq!(
        cache_key(HOST, 5432, "admin", "us-east-1", ROLE, None),
        format!("rds:{HOST}:5432:admin:us-east-1:{ROLE}")
    );
}
```

### exec path routing through the cached fetcher (current `exec.rs`)

```rust
// CORRECT: calls the cached function, not the internal uncached one
super::credential::redshift::fetch_cached_redshift_credentials(
    server, &target, opts.db_name, opts.region, role,
).await
```

### Anchored RDS region extraction (current `rds.rs`)

```rust
fn extract_region_from_rds_hostname(hostname: &str) -> Option<&str> {
    hostname.split('.').find(|label| {
        is_region_shaped(label) && {
            let partition = Partition::from_region(label);
            let tail = if partition == Partition::AwsCn {
                format!(".rds.{label}.{}", partition.dns_suffix())
            } else {
                format!(".{label}.rds.{}", partition.dns_suffix())
            };
            hostname.ends_with(&tail)
        }
    })
}
```

## Scope

- `crates/vouch-cli/src/commands/credential/rds.rs`
- `crates/vouch-cli/src/commands/credential/eks.rs`
- `crates/vouch-cli/src/commands/credential/redshift.rs`
- `crates/vouch-cli/src/commands/credential/aws.rs`
- `crates/vouch-cli/src/commands/credential/codeartifact.rs`
- `crates/vouch-cli/src/commands/credential/wif.rs`
- `crates/vouch-cli/src/commands/exec.rs`
- `crates/vouch-cli/src/commands/env.rs`
- Any future file under `crates/vouch-cli/src/commands/credential/` that introduces a new cacheable AWS credential type
