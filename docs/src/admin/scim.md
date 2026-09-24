# SCIM Provisioning

Vouch supports SCIM 2.0 (RFC 7643/7644) for user provisioning and de-provisioning from external identity providers.

## Setup

The admin API endpoints (`/api/v1/org/*`) require an authenticated Vouch session from a user with org admin privileges. The server accepts the access token via `Authorization: Bearer <token>`, `Authorization: DPoP <token>`, or the `vouch_session` cookie.

**Prerequisites:**
- You must belong to an organization and be an org administrator.

You do not create either by hand. Organizations are created automatically the first time someone
enrolls from a given email domain, and that first enrollee becomes the organization's
administrator. Every administrator after that is promoted from the admin UI. See
[Organizations and Administrators](organizations.md) for the full model.

### 1. Create a SCIM token

The simplest way is the admin UI: go to **`/admin/scim-tokens`**, create a token, and copy it.
Choose an expiry between 1 and 365 days.

To script it instead, call the API with an access token from an admin session:

```bash
curl -X POST https://auth.example.com/api/v1/org/scim-tokens \
  -H "Authorization: Bearer $(vouch credential token)" \
  -H "Content-Type: application/json" \
  -d '{"description": "SCIM integration", "expires_in_days": 90}'
```

Either way the token is prefixed `vouch_scim_` and is **shown once**. It is stored only as a
SHA-256 hash, so it cannot be recovered — if you lose it, revoke it and create another.

### 2. Configure your IdP

Enter the following in your IdP's SCIM configuration:
- **SCIM endpoint URL**: `https://auth.example.com/scim/v2/`
- **Bearer token**: the `vouch_scim_...` token from step 1

### Domain validation

`POST /scim/v2/Users` requires `userName` to be an email address, or `emails[]` to supply one —
Vouch keys users by email, so a value that is neither is rejected with `400` and
`"userName must be an email address"`.

The email's domain must also be one the token's organization has proven it owns: the
organization's primary domain, or an additional domain that has completed DNS TXT verification
(see [Email Domains](domains.md)). A push for any other domain — including a domain that is
merely added but not yet verified, or a subdomain of a verified one — is rejected with `400` and
`"scimType": "invalidValue"`.

This closes an isolation gap rather than adding a new setup step: it matters whenever your IdP
pushes a user whose address isn't already on the org's own domain — provisioning from a second
email domain, or a misconfigured IdP pointed at the wrong tenant. If you provision from more than
one domain, verify each one first at `/admin/domains` before pushing users on it.

### 3. Manage tokens

List and revoke tokens at `/admin/scim-tokens`, or through the API:

```bash
# List active SCIM tokens
curl -H "Authorization: Bearer $(vouch credential token)" \
  https://auth.example.com/api/v1/org/scim-tokens

# Revoke a SCIM token
curl -X DELETE -H "Authorization: Bearer $(vouch credential token)" \
  https://auth.example.com/api/v1/org/scim-tokens/<token-id>
```

Revocation takes effect immediately — tokens are checked against the database on every request.
Expired tokens are removed by the background cleanup task.

## Attribute Updates (PATCH)

`PATCH /scim/v2/Users/{id}` and `PATCH /scim/v2/Groups/{id}` accept `add`, `replace`, and `remove`
operations. Vouch stores a subset of the SCIM schema, and all three operations behave the same way
across it:

| Resource | Attribute path | `add` / `replace` | `remove` |
|----------|----------------|-------------------|----------|
| User | `active` | sets it; a non-boolean is rejected | rejected (`mutability`) |
| User | `name.formatted`, `displayName` | sets the stored name | clears it |
| User | `externalId` | sets it | clears it |
| User | `userName`, `emails` (including `emails[type eq "work"].value`) | accepted only when the value is the user's stored email; any other value is rejected (`mutability`) | rejected (`mutability`) |
| Group | `displayName` | sets it; empty is rejected | rejected (`mutability`) |
| Group | `externalId` | sets it | clears it |
| Group | `members` | `add` adds members; `replace` swaps the whole set | removes every member |
| Group | `members[value eq "<user-id>"]` | `replace` swaps that member for the one in `value`; `add` is rejected (`invalidPath`) | removes that member |

Paths may carry the core schema URN (`urn:ietf:params:scim:schemas:core:2.0:User:userName`), and
attribute names are matched case-insensitively, as RFC 7644 requires. List filters accept the same
qualified names.

List filters (`GET /scim/v2/Users?filter=…`, `GET /scim/v2/Groups?filter=…`) support one comparison
with `eq`, `co`, or `sw` on these attributes:

| Resource | Attributes |
|----------|------------|
| User | `userName` (also accepted as `email`), `externalId` |
| Group | `displayName`, `externalId` |

The value is a JSON string, so a quote or backslash in it is escaped (`displayName eq "Team \"A\""`).
Any other filter — another attribute such as `id` or `emails.value`, another operator, `pr`, or an
`and`/`or`/`not` expression — returns `400` with `"scimType": "invalidFilter"` rather than an
unfiltered list.

An operation with no `path` — a value object such as `{"op": "replace", "value": {"active": false}}` —
sets every attribute in the table the object carries, Group `members` included.

**Any other attribute path is ignored, and the request still returns `200`.** Okta and Entra push
attributes Vouch does not store (`title`, `department`, `name.givenName`, enterprise extensions);
rejecting those would fail an entire provisioning sync over data the directory never keeps. The
consequence for you: a `200` does not by itself prove Vouch stored what the IdP sent. The response
body is the resource as stored — check it when an attribute appears not to sync.

`userName` and `emails` are advertised as `immutable` in `/scim/v2/Schemas`: Vouch keys a user by
their email and cannot change it. An IdP that sends the unchanged address on a routine sync succeeds
(the comparison ignores case); one that sends a different address, removes it, or clears `emails`
gets `400` with `"scimType": "mutability"`. If a user's email changes at the IdP, de-provision and
re-provision them.

`active` is advertised as required. A user has no state without it, so removing it returns `400`
`mutability` rather than silently changing the user's access; RFC 7644 gives removing a required
attribute that error, and it applies to Group `displayName` the same way.

**A `remove` of `members` with no filter and no `value` list empties the group**, as RFC 7644
defines it. Entra's form — `path: "members"` with the members to drop in `value` — removes only
those members.

Other requests rejected with `400`:

| Request | `scimType` |
|---------|------------|
| `remove` with no `path` | `noTarget` |
| `replace` of `members[value eq "<user-id>"]` when that user is not a member | `noTarget` |
| A `members` filter other than `value eq "<user-id>"` | `invalidFilter` |
| `add` or `replace` with no `value`, or a member entry without a string `value` | `invalidValue` |

**A PATCH is all or nothing.** Every operation is applied to the stored resource in order and the
result — attributes and membership together — is written in one transaction, so a `400` or `500`
means nothing in the request was applied. A request that changes nothing (re-adding a current
member, re-sending the current `externalId`) writes nothing and leaves `meta.lastModified` as it
was.

Setting `active` to `false` is the one attribute update with effects beyond the record: it
invalidates the user's sessions, revokes their SSH certificates, and clears their GitHub refresh
token, the same way de-provisioning does. Those revocations run before the record is written, so a
deactivation whose write then fails has still revoked access; retrying the request completes it.

## Replacing Resources (PUT)

`PUT /scim/v2/Users/{id}` and `PUT /scim/v2/Groups/{id}` replace the resource with the body and
return `200` with the stored resource. PUT never creates: an id that does not exist returns `404`.

Attributes the body leaves out are **cleared**, as RFC 7644 §3.5.1 permits:

| Resource | Attribute | Present | Omitted |
|----------|-----------|---------|---------|
| User | `userName` | must be the stored email, or `400 mutability` | `400 invalidSyntax` (required) |
| User | `emails` | every `value` must be the stored email, or `400 mutability` | left as is |
| User | `name` | stored (`formatted`, or `givenName` and `familyName` joined) | cleared |
| User | `externalId` | stored | cleared |
| User | `active` | stored | set to `true` |
| Group | `displayName` | stored; empty is `400 invalidValue` | `400 invalidSyntax` (required) |
| Group | `externalId` | stored | cleared |
| Group | `members` | replaces the whole member set | **every member is removed** |

`id`, `meta`, and `schemas` in the body are ignored.

Two rows change access, so check your IdP sends them:

- A User PUT without `active` makes the user active. A PUT with `"active": false` deactivates the
  user with the same effects as the PATCH described above, including the refusal to deactivate
  the organization's last active admin.
- A Group PUT without `members` empties the group: a PUT states the whole resource, so an absent
  member list means none.

## Error Responses

Every error from `/scim/v2/*` has the RFC 7644 §3.12 JSON body
(`"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"]`, `status` as a string), including
rejections that happen before the request reaches Vouch's SCIM logic:

| Cause | Status | `scimType` |
|-------|--------|------------|
| Body is not valid JSON | `400` | `invalidSyntax` |
| Body omits a required attribute (`userName`, Group `displayName`) | `400` | `invalidSyntax` |
| Body is JSON but an attribute has the wrong type or an empty required value | `400` | `invalidValue` |
| Query parameter has the wrong type (`startIndex=abc`) | `400` | `invalidValue` |
| `Content-Type` is not JSON (`application/scim+json` and `application/json` both work) | `415` | — |
| Body over 64 KiB | `413` | — |
| Resource id that does not exist, including one that is not a UUID | `404` | — |
| Path that is not a SCIM endpoint | `404` | — |
| Method the endpoint does not support (`Allow` lists the supported ones) | `405` | — |
| Rate limit exceeded (`Retry-After` is set) | `429` | — |

SCIM and the `/api/v1/org/*` API share one rate-limit bucket per client IP (20 requests burst,
1 per second).

## De-Provisioning Behavior

When a user is de-provisioned via SCIM (e.g., employee leaves the organization):

| Action | Timing | Effect |
|--------|--------|--------|
| Active sessions invalidated | Immediate | All current sessions for the user are terminated |
| SSH certificates revoked | Immediate | All issued SSH certificates are marked as revoked |
| Enrolled authenticators deleted | Immediate | All registered credentials are removed (cascade) |
| User record deleted | Immediate | User cannot re-enroll or authenticate |
| Audit event logged | Immediate | De-provisioning recorded with SCIM token info |

Nothing waits for session expiry: access ends when the IdP sends the delete.

## SCIM Endpoint Authentication

SCIM endpoints require bearer token authentication:

**Endpoint**: every `/scim/v2/*` route — `Users` and `Groups`, with `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.

**Authentication**:
- Bearer token in the `Authorization` header
- Token created in the admin UI or via `POST /api/v1/org/scim-tokens`
- Expiry is operator-chosen at creation, between 1 and 365 days
- Use a separate token per IdP integration, so one can be revoked without disturbing the others

```bash
# Example SCIM request
curl -X DELETE https://auth.example.com/scim/v2/Users/0192f1a8-7c3e-7d4a-9b2e-5f6a7b8c9d0e \
  -H "Authorization: Bearer vouch_scim_..." \
  -H "Content-Type: application/scim+json"
```

**Token Security**:
- Tokens are hashed (SHA-256) before storage
- Shown once at creation, never retrievable after
- Bound to specific organization
- Minimum 256 bits of entropy

## Concurrent Provisioning

User creation validates domain ownership inside a transaction keyed on the
organization record, so heavy concurrent provisioning (an IdP bulk-syncing
many users at once) or simultaneous domain changes can occasionally collide.
When the server exhausts its internal retries it responds with
`503 Service Unavailable` and a `Retry-After` header: this is transient
backpressure, not a fault. Okta and Entra retry such
responses automatically; no operator action is needed unless 503s persist,
which indicates sustained contention on the organization (for example, a
domain-management script running during a bulk sync).

Group writes behave the same way per group: two PATCH or PUT requests for one
group at the same moment collide on the group record, and one retries against
the other's result so neither loses the other's member changes. Exhausted
retries return the same `503` with `Retry-After`.

## SCIM Audit Logging

All SCIM operations are logged for compliance and security monitoring:

| Operation | Resource Type | Logged Data |
|-----------|--------------|-------------|
| `create` | `User` | resource_id, scim_token_id, timestamp |
| `update` | `User` | resource_id, scim_token_id, timestamp (PATCH) |
| `replace` | `User` | resource_id, scim_token_id, timestamp (PUT) |
| `delete` | `User` | resource_id, scim_token_id, timestamp |
| `create` | `Group` | resource_id, display_name, scim_token_id, timestamp |
| `update` | `Group` | resource_id, scim_token_id, timestamp (PATCH) |
| `replace` | `Group` | resource_id, scim_token_id, timestamp (PUT) |
| `delete` | `Group` | resource_id, scim_token_id, timestamp |

## SCIM vs Manual Enrollment

| Aspect | SCIM Provisioning | Manual Enrollment |
|--------|-------------------|-------------------|
| User record creation | IdP pushes user info | User initiates enrollment |
| Hardware enrollment | Still requires physical hardware key | Requires physical hardware key |
| De-provisioning | Immediate via IdP (user deleted, sessions invalidated, certs revoked) | Manual admin action (sessions invalidated, certs revoked) |
| Group membership | Synced from IdP | Not available outside SCIM |

**Note**: SCIM pre-provisioning creates a user record, but they still cannot authenticate until they physically enroll a hardware FIDO2 authenticator. The security model remains: no credential without hardware.
