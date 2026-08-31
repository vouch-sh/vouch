# AWS Credential Cache Key Missing Agent Source

Detect AWS credential cache keys that are constructed without the `agent_source` context, which allows human and AI-agent invocations to share a cached token and bypasses the `ReadOnlyAccess` session policy and `vouch:AccessType=ai` / `vouch:Agent` principal tags applied to agent-sourced credentials.

## What to look for

In every credential flow that calls `cache::get_or_fetch(...)`, the following invariant must hold:

1. **`detect_agent_source()` is called BEFORE `cache::get_or_fetch`**, not inside the fetch closure. The fetch closure only runs on a cache miss, so detecting the agent inside it means a prior non-agent cache hit is returned without the agent restrictions applied.

2. **The result of `detect_agent_source()` is folded into the cache key** before `get_or_fetch` is called. The agent suffix pattern used across this codebase is:
   ```
   :agent:{src}
   ```
   appended to the base key.

3. **The detected `agent_source` value is passed as a parameter to the inner fetch function** (e.g., `fetch_and_assume`, `generate_eks_token`, `generate_rds_token`, `fetch_redshift_credentials`, `fetch_token`) rather than re-detected inside that function.

The affected files are in `crates/vouch-cli/src/commands/credential/` and `crates/vouch-cli/src/commands/exec.rs`. Any file in those directories that:
- calls `cache::get_or_fetch`
- ultimately calls `exchange_for_sts_credentials` (which accepts `StsRequest { agent_source, .. }`)

...must follow this pattern.

**Key indicator of a violation:** A `cache_key` `format!` string that does not include `agent_suffix` or an `:agent:` component, combined with either (a) `detect_agent_source()` being called inside the fetch closure, or (b) the agent detection being absent from the outer function entirely.

## Violation examples

**Pattern A — STS/AWS (issue #398): agent detection inside fetch closure, cache key has no agent suffix**

```rust
// VIOLATION: cache_key built without agent context
let cache_key = if let Some(ref mgmt_role) = management_role {
    format!("aws:chain:{mgmt_role}:{role_arn}")
} else {
    format!("aws:{role_arn}")
};

super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
    // detect_agent_source() called here — only runs on cache miss!
    let output = fetch_and_assume(server, role_arn, mgmt.as_deref()).await?;
    ...
})
```

Inside `fetch_and_assume` / `exchange_for_sts_credentials`:
```rust
// VIOLATION: agent detection buried inside the uncached path
let agent_source = detect_agent_source();
let agent_policies = if agent_source.is_some() { &["ReadOnlyAccess"] } else { &[] };
```

**Pattern B — EKS (issue #426): cache key lacks agent suffix**

```rust
// VIOLATION: no agent suffix in key
let cache_key = format!("eks:{cluster_name}:{role_arn}");

let data = cache::get_or_fetch(&cache_key, "EKS token", || async {
    let token = generate_eks_token(server, cluster_name, &region_name, &role_arn).await?;
    ...
})
```

Inside `generate_eks_token`:
```rust
// VIOLATION: detection inside the fetch function, not at the cache-key site
let agent_source = crate::commands::credential::aws::detect_agent_source();
let result = exchange_for_sts_credentials(StsRequest { ..., agent_source: agent_source.as_deref() }).await?;
```

**Pattern C — Redshift (issue #426): cache key lacks agent suffix**

```rust
// VIOLATION: no :agent: component in either key variant
let cache_key = match &target {
    RedshiftTarget::Cluster { cluster_id, .. } => format!("redshift:{cluster_id}:{role_arn}"),
    RedshiftTarget::Serverless { workgroup }    => format!("redshift-serverless:{workgroup}:{role_arn}"),
};
```

**Pattern D — CodeArtifact (issue #716): detection inside `fetch_token`, not before cache lookup**

```rust
// VIOLATION: agent not in key, detection deferred to inner fetch
let cache_key = format!("codeartifact:{domain}:{domain_owner}:{region}");

let data = cache::get_or_fetch(&cache_key, "CodeArtifact token", || async {
    let token = fetch_token(server, domain, domain_owner, region).await?;
    ...
})
```

Inside `fetch_token`:
```rust
// VIOLATION: detect_agent_source called only on cache miss
let agent_source = crate::commands::credential::aws::detect_agent_source();
let result = exchange_for_sts_credentials(StsRequest { ..., agent_source: agent_source.as_deref() }).await?;
```

## Correct patterns

**Correct STS/AWS pattern** (`aws.rs`):

```rust
// Detect BEFORE cache lookup, fold into key
let agent_source = detect_agent_source();
let cache_key = build_cache_key(role_arn, management_role.as_deref(), agent_source.as_deref());

let agent = agent_source;
super::cache::get_or_fetch(&cache_key, "AWS credentials", || async move {
    let output = fetch_and_assume(server, role_arn, mgmt.as_deref(), agent.as_deref()).await?;
    ...
})
```

The `build_cache_key` helper (in `aws.rs`) produces:
- `aws:{role_arn}` (no agent, no chain)
- `aws:chain:{mgmt}:{role_arn}` (no agent, with chain)
- `aws:{role_arn}:agent:{src}` (agent, no chain)
- `aws:chain:{mgmt}:{role_arn}:agent:{src}` (agent, with chain)

**Correct EKS pattern** (`eks.rs`):

```rust
let agent_source = crate::commands::credential::aws::detect_agent_source();
let agent_suffix = agent_source.as_deref().map_or(String::new(), |src| format!(":agent:{src}"));
let cache_key = format!("eks:{cluster_name}:{role_arn}{agent_suffix}");

let agent = agent_source;
let data = cache::get_or_fetch(&cache_key, "EKS token", || async {
    let token = generate_eks_token(server, cluster_name, &region_name, &role_arn, agent.as_deref()).await?;
    ...
})
```

`generate_eks_token` accepts `agent_source: Option<&str>` as a parameter instead of calling `detect_agent_source()` internally.

**Correct CodeArtifact pattern** (`codeartifact.rs`):

```rust
let agent_source = crate::commands::credential::aws::detect_agent_source();
let cache_key = build_cache_key(domain, domain_owner, region, agent_source.as_deref());

let agent = agent_source;
let data = cache::get_or_fetch(&cache_key, "CodeArtifact token", || async {
    let token = fetch_token(server, domain, domain_owner, region, agent.as_deref()).await?;
    ...
})
```

Where `build_cache_key` produces `codeartifact:{domain}:{domain_owner}:{region}:agent:{src}` when an agent is present.

## Scope

Check all files under:

- `crates/vouch-cli/src/commands/credential/aws.rs`
- `crates/vouch-cli/src/commands/credential/eks.rs`
- `crates/vouch-cli/src/commands/credential/rds.rs`
- `crates/vouch-cli/src/commands/credential/redshift.rs`
- `crates/vouch-cli/src/commands/credential/codeartifact.rs`
- `crates/vouch-cli/src/commands/credential/docker.rs` (uses `exchange_for_sts_credentials` without a cache — verify agent detection still occurs before the call)
- `crates/vouch-cli/src/commands/aws/console.rs` (uses `exchange_for_sts_credentials` without a cache — verify agent detection still occurs before the call)
- `crates/vouch-cli/src/commands/exec.rs` (calls credential helpers — verify agent detection is passed through, not re-detected inside helpers)

Any **new** credential helper file added under `crates/vouch-cli/src/commands/credential/` that:
1. calls `cache::get_or_fetch`, and
2. eventually calls `exchange_for_sts_credentials`

must also follow this pattern.
