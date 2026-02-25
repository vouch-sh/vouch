# Incident Response

This chapter describes Vouch's incident severity classification, response procedures, and communication channels for security events.

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| **Critical** | Active exploitation, credential theft | 1 hour |
| **High** | Exploitable vulnerability, no active exploitation | 24 hours |
| **Medium** | Vulnerability requiring unlikely conditions | 7 days |
| **Low** | Minor issues, defense in depth | 30 days |

## Response Procedure

1. **Triage** — Assess severity and scope
2. **Contain** — Revoke affected credentials, disable vulnerable features
3. **Investigate** — Root cause analysis
4. **Remediate** — Deploy fix
5. **Communicate** — Notify affected users
6. **Review** — Post-incident analysis

## Communication Channels

- **Security advisories**: https://vouch.sh/security
- **CVE assignments**: Via GitHub Security Advisories
- **Status page**: https://status.vouch.sh
