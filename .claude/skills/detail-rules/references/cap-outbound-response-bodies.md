# Cap Outbound HTTP Response Bodies While Streaming

Detect reads of a remote HTTP response body that let the remote host decide how much memory the server allocates — either no size cap at all, or a cap checked only after the whole body has been buffered. This causes memory-exhaustion denial of service, because a hostile or compromised host can stream until the request timeout and be rejected only once the allocation has already happened.

## What to look for

Any call in `crates/vouch-server/src/` that awaits one of `reqwest::Response`'s collecting body accessors is a violation:

```
response.bytes().await
response.text().await
response.text_with_charset(..).await
response.json().await
response.json::<T>().await
response.bytes_stream()      // when collected without a running limit
```

All of these read the entire body into memory before returning. The only sanctioned readers are in `crates/vouch-server/src/infra/egress.rs` — `read_capped_bytes`, `read_capped_text`, `read_capped_json`, and `read_error_body` — which poll `reqwest::Response::chunk()` and abort once the running length crosses a caller-supplied limit.

**Specific conditions that constitute a violation:**

1. **A `Content-Length` pre-check followed by a collecting accessor.** This is the highest-value shape to flag, because it *looks* correct:

   ```rust
   if let Some(len) = response.content_length()
       && len > MAX_SIZE as u64
   {
       return Err(...);
   }
   let body = response.bytes().await?;   // violation
   if body.len() > MAX_SIZE { return Err(...); }
   ```

   `content_length()` returns `None` for a `Transfer-Encoding: chunked` response, so the pre-check silently does not run, and the post-read check fires only after the full body is in memory. The guard is bypassed by the transfer encoding alone — no malformed input required.

2. **A post-read length check.** Any `body.len() > LIMIT` / `bytes.len() > LIMIT` test that appears *after* the accessor. By then the allocation has happened; the check bounds what is returned, not what is allocated.

3. **No cap at all.** A collecting accessor with no size constant anywhere in the function. Grade the severity by who controls the URL, but flag all of them:
   - URL from an unauthenticated registration or a request parameter (a client `jwks_uri`, an OIDC `request_uri`) — directly reachable.
   - URL read out of a document fetched over the network (an upstream IdP's `jwks_uri`, taken from its discovery document) — reachable by whoever controls that host.
   - URL from operator configuration or a fixed vendor host — hardening, not a live attack, but still an unbounded allocation.

4. **A diagnostic body read on an error path.** `response.text().await.unwrap_or_default()` used only to build a log line is still unbounded, and an error path is exactly where a hostile host would put a body it wants buffered. Use `read_error_body`, which caps and degrades to an empty string.

5. **Truncation after the fact.** `body.chars().take(200)` bounds the log line, not the allocation that produced it.

**What is safe (not a violation):**

- Any call into `crate::infra::egress::read_capped_*` or `read_error_body`.
- Code inside `crates/vouch-server/src/infra/egress.rs` itself — that module owns the streaming reader.
- `.json(&payload)` on a `RequestBuilder`. This sets a *request* body and takes an argument; it is not a response read.
- `str::bytes()` and `Element::text()` — iterator and accessor methods that share a name with the reqwest accessors but are not futures. Require an `.await` before flagging.
- Body reads inside `#[cfg(test)]` modules, which drive fixtures rather than attacker input.
- Reads in `vouch-cli` and `vouch-agent`, where the process is short-lived, single-user, and not a shared availability target. Prefer capping there too, but do not report it at the same severity.

## Why this matters

A size limit that is enforced after buffering is not a limit. The window between "bytes arrive" and "check runs" is where the attack lives, and the request timeout bounds only wall time — an attacker with bandwidth converts that time into allocation. Concurrent requests from multiple source IPs accumulate, and a per-IP rate limit does not bound the total.

The fix is structural rather than per-site: enforce the cap *during* the read so there is no window, and route every call site through one reader so a new site cannot reintroduce the gap.

## Related

- Issue #1105 — the original report, against the client `jwks_uri` fetch in `infra/jwks.rs`.
- `crates/vouch-server/tests/egress_body_caps.rs` — build-time ratchet that fails if any module outside `infra/egress.rs` awaits a collecting accessor. Report a violation of this rule even when that test passes; the ratchet matches text and can be evaded by an alias or a re-export.
- Time is bounded separately from bytes: `vouch_common::http::server_client` sets a total timeout, a connect timeout, and a read (idle-gap) timeout. A size cap does not bound how long a slow-drip host holds a connection, and a timeout does not bound how much it allocates. Both are required; flag a new outbound client built without timeouts as a related defect.
