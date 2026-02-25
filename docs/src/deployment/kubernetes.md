# Kubernetes (Helm)

Deploy Vouch on Kubernetes using the Helm chart.

## Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3
- A persistent volume provisioner (for SQLite) or external PostgreSQL

## Install

```bash
# Add the Vouch Helm repository
helm repo add vouch https://charts.vouch.sh
helm repo update

# Install
helm install vouch-server vouch/vouch-server \
  --namespace vouch \
  --create-namespace \
  --set config.rpId=auth.example.com \
  --set config.jwtSecret=<your-secret> \
  --set config.baseUrl=https://auth.example.com
```

## Values

Key values to configure:

```yaml
# values.yaml
image:
  repository: ghcr.io/vouch-sh/vouch
  tag: latest

config:
  rpId: auth.example.com
  rpName: "My Organization"
  baseUrl: https://auth.example.com
  sessionHours: 8

# Database
database:
  # SQLite (default, with PVC)
  type: sqlite
  # Or PostgreSQL
  # type: postgres
  # url: postgres://user:pass@host:5432/vouch

# TLS (if not using ingress TLS termination)
tls:
  enabled: false
  # cert: <base64-encoded>
  # key: <base64-encoded>

# SSH CA
sshCa:
  enabled: true
  # key: <base64-encoded>

# Secrets (reference existing K8s secrets)
existingSecret: vouch-secrets
# The secret should contain keys: jwt-secret, ssh-ca-key, tls-cert, tls-key

# Ingress
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vouch-tls
      hosts:
        - auth.example.com

# Resources
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi

# Persistence (for SQLite)
persistence:
  enabled: true
  size: 1Gi
  storageClass: gp3
```

## Using Kubernetes Secrets

Create secrets for sensitive values:

```bash
kubectl create secret generic vouch-secrets \
  --namespace vouch \
  --from-literal=jwt-secret='<your-64-character-secret>' \
  --from-file=ssh-ca-key=./ssh_ca_key \
  --from-file=tls-cert=./tls_cert.pem \
  --from-file=tls-key=./tls_key.pem
```

Then reference in values:

```yaml
existingSecret: vouch-secrets
```

## Air-Gapped Kubernetes

For air-gapped environments:

1. Save and transfer the chart:
   ```bash
   helm pull oci://ghcr.io/vouch-sh/charts/vouch-server --version 0.1.0
   # Transfer vouch-server-0.1.0.tgz to air-gapped environment
   ```

2. Save and transfer the container image:
   ```bash
   docker pull ghcr.io/vouch-sh/vouch:1.0.0
   docker save ghcr.io/vouch-sh/vouch:1.0.0 -o vouch-1.0.0.tar
   # Transfer and load into your private registry
   ```

3. Install from the local chart:
   ```bash
   helm install vouch-server ./vouch-server-0.1.0.tgz \
     --namespace vouch \
     --create-namespace \
     --set image.repository=registry.internal/vouch \
     --values my-values.yaml
   ```

## Upgrading

```bash
helm repo update
helm upgrade vouch-server vouch/vouch-server \
  --namespace vouch \
  --values my-values.yaml
```

## Health Checks

The chart configures liveness and readiness probes against the `/health` endpoint.
