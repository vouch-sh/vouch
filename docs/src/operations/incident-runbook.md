# Security Incident Runbook

Procedures for containing a security incident on a Vouch deployment you operate. Each section is
self-contained: find the scenario, follow the steps.

Two properties of Vouch shape everything here. Credentials are short-lived, so many problems bound
themselves within hours. And nothing Vouch issues can be re-issued without a hardware key present,
so revoking access does not create a recovery problem for legitimate users — they just log in
again.

## Triage: what was actually exposed?

| Compromised | Blast radius | Section |
|---|---|---|
| A user's laptop or session | That user's credentials only. Access tokens are DPoP-bound, so a stolen token without the client key is unusable. | [One user](#one-user-is-compromised) |
| A user's YubiKey (lost or stolen) | Nothing without their PIN — the key locks after 8 failed attempts. | [One user](#one-user-is-compromised) |
| The SSH CA private key | An attacker can mint SSH certificates for any principal. | [SSH CA key](#the-ssh-ca-key-is-compromised) |
| An OIDC signing key | An attacker can mint access tokens and AWS federation assertions. | [Signing keys](#a-signing-key-is-compromised) |
| The JWT secret | An attacker can forge authorization codes and CSRF state. | [JWT secret](#the-jwt-secret-is-compromised) |
| A SCIM token | An attacker can create and delete users in your organization. | [SCIM token](#a-scim-token-is-compromised) |
| The database | Read access to audit history and token hashes. No usable private keys — they are not stored there. | [Database](#the-database-is-exposed) |
| The document encryption KMS key | On an encrypted deployment, everything sealed by it. | [Document key](#the-document-encryption-key-is-compromised) |

## One user is compromised

Fastest containment, from the admin UI at `/admin`:

1. **Deactivate** the member. This immediately deletes all their sessions, revokes all their SSH
   certificates, and clears their stored GitHub refresh token. Their enrolled authenticators
   survive, so it is reversible.
2. If their hardware key itself is unaccounted for, use **Revoke credentials** instead — it does
   everything Deactivate does *and* deletes their enrolled authenticators, so the missing key
   cannot be used even by someone who learns the PIN.
3. Review `/admin/audit` filtered to that user for what was issued before containment: look for
   `ssh_credential`, `aws_credential`, `github_credential`, and `token_exchange`.
4. Revoke downstream credentials that outlive Vouch's — AWS STS sessions in particular do not
   expire when the Vouch session does. Revoke them in the IAM console.
5. When the user is ready to return, **Activate** them (after a Deactivate) or have them enroll a
   new key (after Revoke credentials).

See [Organizations and Administrators](../admin/organizations.md#member-actions) for exactly what
each action does.

## The SSH CA key is compromised

An attacker holding this key can sign certificates for any principal on every host that trusts your
CA. Treat as critical.

1. **Generate a new CA key** on a trusted machine:

   ```bash
   ssh-keygen -t ed25519 -f ssh_ca_key.new -N "" -C "vouch-ca@example.com"
   ```

2. **Distribute the new public key** to every host, *alongside* the old one initially:

   ```bash
   cat ssh_ca_key.new.pub >> /etc/ssh/vouch-ca.pub
   ```

3. **Switch the server** to the new key (`VOUCH_SSH_CA_KEY`, `VOUCH_SSH_CA_KEY_PATH`, or
   `VOUCH_SSH_CA_KMS_KEY_ID`) and restart.

4. **Remove the old public key** from every host. Do this immediately in a compromise — the usual
   advice to wait for outstanding certificates to expire assumes the old CA is trustworthy, and
   here it is not. Users re-run `vouch login` to get certificates from the new CA.

5. **Audit for abuse.** Certificates minted by an attacker with the stolen key never touched your
   server, so they are *not* in `/admin/audit`. Compare host `sshd` logs against the
   `ssh_credential` events Vouch recorded; a successful certificate login with no corresponding
   issuance event is a forged certificate.

If the key was in KMS rather than on disk, the private material never left KMS — disable the key
and check CloudTrail for unexpected `kms:Sign` calls instead of assuming compromise.

### Revoking individual certificates

Vouch publishes a revocation list, unauthenticated so hosts can poll it:

```bash
curl https://auth.example.com/v1/credentials/ssh/krl
# {"revoked_serials":[...],"total":N,"generated_at":"..."}

curl https://auth.example.com/v1/credentials/ssh/krl/<serial>
```

Certificates are revoked as a side effect of the member actions above, not through a standalone
endpoint.

## A signing key is compromised

Applies to `VOUCH_OIDC_SIGNING_KEY` (ES256, access and ID tokens) and
`VOUCH_OIDC_RSA_SIGNING_KEY` (RS256, AWS credential tokens).

1. Generate a replacement — see [Signing Keys](../configuration/keys.md).
2. Update the configuration on **every** instance and restart. Mismatched keys across instances
   cause intermittent verification failures; see
   [Running Multiple Instances](high-availability.md).
3. The JWKS endpoint (`/oauth/jwks`) serves the new public key immediately, but relying parties
   cache it. AWS in particular caches JWKS for an undocumented period exceeding the advertised
   1-hour `Cache-Control`, so federation may fail until it refetches.
4. All previously issued tokens become invalid. Users run `vouch login` again.
5. If the RS256 key was exposed, review CloudTrail for `AssumeRoleWithWebIdentity` calls you cannot
   attribute to an `aws_credential` audit event.

## The JWT secret is compromised

`VOUCH_JWT_SECRET` signs authorization codes, WebAuthn challenge state, and CSRF tokens.

1. Generate a new secret: `openssl rand -base64 48`
2. Update every instance and restart.
3. **Every session is invalidated** and all users must run `vouch login` again. There is no
   graceful rotation.

Consider moving to `VOUCH_JWT_HMAC_KMS_KEY_ID` afterwards, so the secret never exists as an
environment variable again.

## A SCIM token is compromised

A SCIM token can create and delete users in your organization.

1. Revoke it at `/admin/scim-tokens`. Revocation takes effect immediately — tokens are checked
   against the database on every request.
2. Issue a replacement and update your IdP's SCIM configuration.
3. Review `/admin/audit` for `scim_operation` events, particularly user deletions you did not
   expect.

Tokens are stored as SHA-256 hashes, so a database leak does not itself expose usable tokens.

## The database is exposed

The database holds audit history, user records, session records, and hashed tokens. It does **not**
hold usable private key material: the SSH CA and OIDC signing keys come from the environment, S3
configuration, or KMS, and on an encrypted deployment the documents themselves are sealed with a
KMS-held key.

1. Rotate the JWT secret — session records are keyed against it.
2. Rotate all SCIM tokens.
3. Rotate OAuth client secrets for every registered application.
4. Treat audit history as disclosed: it contains domain-masked emails, IP addresses, and geographic
   metadata.
5. Enrolled WebAuthn credentials are public keys. They are not secret and need no rotation.

## The document encryption key is compromised

On a deployment using S3 configuration with a `document_key`, a single KMS customer master key
seals every stored document. Compromise of that key is compromise of everything it sealed.

1. Disable the KMS key and review CloudTrail for `kms:Decrypt` calls you cannot account for.
2. Rotate every secret the documents contained: OAuth client secrets, SCIM tokens.
3. There is no in-place document-key rotation mechanism. Provisioning a replacement requires
   `vouch-server generate-document-key` and a coordinated re-encryption.

> **Do not delete the old KMS key.** Documents sealed with it become permanently unreadable, and
> that includes your audit history. See
> [Backup and Recovery](backup-recovery.md).

## Certification test mode found enabled in production

If a production server logs the certification test-mode warning at startup, or
`/certification/complete-login` responds:

1. Treat it as an active authentication bypass. It mints sessions for a synthetic user with no
   hardware key, and it disables all rate limiting.
2. Unset `VOUCH_CERTIFICATION_TEST_TOKEN` and restart immediately.
3. Rotate the JWT secret to invalidate any session minted through the bypass.
4. Review `/admin/audit` for `login_success` events with no `authenticator_id`.

See [Security Hardening](security-hardening.md#certification-test-mode).

## Gathering evidence

```bash
# SQLite
sqlite3 /data/vouch.db \
  "SELECT * FROM audit_events WHERE created_at > datetime('now','-7 days') ORDER BY created_at;"

# PostgreSQL
psql "$VOUCH_DATABASE_URL" -c \
  "SELECT * FROM audit_events WHERE created_at > now() - interval '7 days' ORDER BY created_at;"
```

Administrative and organization-lifecycle events are never purged by retention, so the record of
who granted whom access survives regardless of your retention settings. Authentication and
credential events follow `VOUCH_AUTH_EVENTS_RETENTION_DAYS` and
`VOUCH_OAUTH_EVENTS_RETENTION_DAYS` — if you need a long forensic window, raise them *before* you
need it.

Correlate application logs by `x-fapi-interaction-id`; see
[Monitoring and Metrics](monitoring.md#correlating-requests).

## Reporting a vulnerability in Vouch itself

This runbook covers incidents in *your* deployment. To report a security vulnerability in the Vouch
software, see the security policy at [vouch.sh](https://vouch.sh).
