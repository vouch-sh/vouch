# Kubernetes (Helm)

Deploy Vouch on Kubernetes using the Helm chart.

## Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3
- A persistent volume provisioner (for SQLite) or external PostgreSQL

## Install

```bash
# Install from OCI registry
helm install vouch-server oci://ghcr.io/vouch-sh/charts/vouch-server \
  --version 0.1.0 \
  --namespace vouch \
  --create-namespace \
  --values my-values.yaml
```

## Values

Key values to configure:

```yaml
# values.yaml
image:
  repository: ghcr.io/vouch-sh/vouch
  pullPolicy: IfNotPresent
  tag: ""  # defaults to chart appVersion

serviceAccount:
  create: true
  annotations: {}

podSecurityContext:
  fsGroup: 65532

securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65532
  seccompProfile:
    type: RuntimeDefault

service:
  type: ClusterIP
  port: 3000

# Environment variables for vouch-server
env:
  VOUCH_LISTEN_ADDR: "0.0.0.0:3000"
  VOUCH_DATABASE_URL: "sqlite:/data/vouch.db?mode=rwc"
  VOUCH_RP_ID: "auth.example.com"
  VOUCH_BASE_URL: "https://auth.example.com"
  RUST_LOG: "info,vouch_server=debug"

# Secret environment variables
# Reference an existing secret containing keys like:
# - VOUCH_JWT_SECRET
# - VOUCH_OIDC_ISSUER
# - VOUCH_OIDC_CLIENT_ID
# - VOUCH_OIDC_CLIENT_SECRET
existingSecret: ""

# Or create a new secret (not recommended for production)
secrets: {}
  # VOUCH_JWT_SECRET: ""

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
  existingClaim: ""
  storageClass: ""
  accessMode: ReadWriteOnce
  size: 1Gi
  mountPath: /data

# Health check configuration
healthcheck:
  path: /health
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

## Using Kubernetes Secrets

Create secrets for sensitive values:

```bash
kubectl create secret generic vouch-secrets \
  --namespace vouch \
  --from-literal=VOUCH_JWT_SECRET='<your-64-character-secret>' \
  --from-literal=VOUCH_OIDC_ISSUER='https://accounts.google.com' \
  --from-literal=VOUCH_OIDC_CLIENT_ID='...' \
  --from-literal=VOUCH_OIDC_CLIENT_SECRET='...'
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
   docker pull ghcr.io/vouch-sh/vouch:0.1.0
   docker save ghcr.io/vouch-sh/vouch:0.1.0 -o vouch-0.1.0.tar
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
helm upgrade vouch-server oci://ghcr.io/vouch-sh/charts/vouch-server \
  --version <new-version> \
  --namespace vouch \
  --values my-values.yaml
```

## Health Checks

The chart configures liveness and readiness probes against the `/health` endpoint.
