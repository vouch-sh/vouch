# Email Domains

An organization is created from the email domain of its first enrollee. That domain is the
organization's **primary domain** and cannot be changed. If your users have email addresses on more
than one domain — an acquisition, a rebrand, a regional subsidiary — you add those as **additional
domains** so their enrollments attach to the same organization.

Manage them at `/admin/domains`.

## Why verification exists

Claiming a domain determines which organization a user's enrollment joins, and therefore which
administrators can act on that user. Without proof of ownership, anyone could claim
`competitor.com`, wait for one of their employees to enroll, and take administrative control of
that account.

So an added domain does nothing until it is verified. Until then it is not indexed and takes no
part in matching users at login: users on that domain continue to enroll exactly as if you had
never added it.

## Adding and verifying a domain

1. **Add the domain** on `/admin/domains`. The server generates a random token and the entry
   enters the `Pending` state.

2. **Publish the DNS TXT record.** Create a TXT record at:

   ```
   _vouch-verification.<your-domain>
   ```

   with the token shown in the UI as its value. For `example.com` that is
   `_vouch-verification.example.com`.

3. **Click Verify.** The server performs a DNS TXT lookup and marks the entry `Verified` if any
   record at that name matches the token. If the lookup fails or nothing matches, the entry stays
   pending and you can retry after fixing DNS.

Once verified, new enrollments from that domain join this organization.

An organization may hold up to **10** additional domains, on top of its primary domain.

> **Leave the TXT record published.** It is not a one-time check — the server re-verifies it
> periodically, and removing the record will eventually unverify the domain. See below.

## Domain states

| State | Meaning | Counts for login matching |
|-------|---------|---------------------------|
| **Pending** | Added, TXT record never yet observed | No |
| **Verified** | Ownership confirmed | Yes |
| **Unverified** | Was verified, then failed re-verification repeatedly | No |

Only `Verified` entries — plus the primary domain — make up the organization's owned domain set.
This same set gates [SCIM user provisioning](scim.md#domain-validation): an IdP token can only
create users whose email domain is in it.

## Ongoing re-verification

A background task re-checks the DNS TXT record of every verified additional domain. It runs as
part of the general cleanup pass (`VOUCH_CLEANUP_INTERVAL`, 15 minutes by default), but any
individual domain is re-checked at most once every **24 hours**.

After **3 consecutive failures**, the entry flips to `Unverified`:

- New logins stop attaching to your organization for that domain.
- **Users who already enrolled keep their organization membership.** They are not orphaned,
  deactivated, or removed. This is deliberate — a DNS outage must not evict your existing users.
- An `org_domain_unverified` audit event is recorded.

A single successful check resets the failure counter to zero, so a brief DNS blip costs nothing.

## Automatic cleanup

Two garbage-collection rules keep abandoned entries from accumulating:

| Entry | Deleted after | Audit event |
|-------|---------------|-------------|
| `Pending` — added but never verified | 7 days | `org_domain_expired` |
| `Unverified` — auto-unverified by failed re-checks | 14 days | `org_domain_expired` |

Deletion here only removes the claim; it never touches users.

## Removing a domain

Remove a domain from `/admin/domains`. This unclaims it — future enrollments from that domain no
longer join your organization — and records `org_domain_removed`. Existing users keep their
organization membership, exactly as with unverification.

## Audit events

| Event | Trigger |
|-------|---------|
| `org_domain_added` | Domain added, entering pending |
| `org_domain_verified` | TXT record matched, entry verified |
| `org_domain_removed` | Administrator removed the domain |
| `org_domain_unverified` | Re-verification failed 3 times in a row |
| `org_domain_expired` | Garbage-collected as a stale pending or unverified entry |

See [Audit Events](audit.md) for how to browse and retain these.

## Troubleshooting

**Verify fails but the record looks correct.**
Check propagation from the server's own resolver, not your workstation:
`dig +short TXT _vouch-verification.example.com`. The value must match the token exactly. Some DNS
providers append the zone name automatically — if you enter `_vouch-verification.example.com` in a
zone that already appends `example.com`, you end up with
`_vouch-verification.example.com.example.com`.

**A domain unverified itself.**
The TXT record was unreachable on 3 consecutive daily checks. Republish it and click Verify again.
Existing users on that domain were unaffected.

**A domain disappeared from the list.**
It was pending for more than 7 days, or unverified for more than 14, and was garbage-collected.
Re-add it; you will get a fresh token.
