# SSH Certificates

This chapter describes how Vouch integrates with SSH using short-lived certificates issued by the built-in SSH Certificate Authority.

## Configuration

```
~/.ssh/config:
  Host *
    IdentityAgent ~/.vouch/ssh-agent.sock

How it works:
1. SSH client connects to vouch's agent socket
2. vouch-agent returns cached SSH certificate
3. If expired, fetches new cert from server (session required)
4. SSH proceeds with standard certificate authentication
5. Server validates cert against trusted CA
```

## Setup

**`vouch setup ssh` creates:**
- SSH keypair at `~/.ssh/id_ed25519_vouch`
- Config entry pointing to vouch's SSH agent socket
- Outputs CA public key for host configuration

## Host-Side Configuration

```bash
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/vouch-ca.pub
```
