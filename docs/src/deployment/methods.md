# Deployment Methods

Choose a deployment method based on your infrastructure:

| Method | Best For | Complexity |
|--------|----------|------------|
| [Systemd (Bare Metal)](systemd.md) | Single server, VMs, on-premises | Low |
| [Docker](docker.md) | Container-based environments | Low |
| [Kubernetes (Helm)](kubernetes.md) | Multi-node, high availability, cloud-native | Medium |

All methods use the same Vouch server binary and configuration via environment variables. The deployment method only affects how the process is managed and how configuration is provided.

## Verification

Regardless of deployment method, verify the server is running:

```bash
# Health check
curl -k https://auth.example.com/health
# Expected: {"status":"healthy"}

# SSH CA public key (if configured)
curl -k https://auth.example.com/.well-known/ssh-ca.pub
# Expected: ssh-ed25519 AAAA... vouch-ca@...

# OIDC discovery
curl -k https://auth.example.com/.well-known/openid-configuration
# Expected: JSON discovery document
```
