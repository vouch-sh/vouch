# Docker

Deploy Vouch using Docker or Docker Compose.

## Docker Run

```bash
docker run -d \
  --name vouch-server \
  --restart unless-stopped \
  -p 443:443 \
  -v vouch-data:/data \
  -e VOUCH_RP_ID=auth.example.com \
  -e VOUCH_JWT_SECRET=<your-64-character-secret> \
  -e VOUCH_DATABASE_URL=sqlite:/data/vouch.db?mode=rwc \
  -e VOUCH_TLS_CERT=<base64-encoded-certificate> \
  -e VOUCH_TLS_KEY=<base64-encoded-private-key> \
  ghcr.io/vouch-sh/vouch:latest
```

## Docker Compose

```yaml
# docker-compose.yml
services:
  vouch-server:
    image: ghcr.io/vouch-sh/vouch:latest
    container_name: vouch-server
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - vouch-data:/data
    env_file:
      - vouch.env
    environment:
      VOUCH_DATABASE_URL: sqlite:/data/vouch.db?mode=rwc
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "--no-check-certificate", "https://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  vouch-data:
```

Create a `vouch.env` file:

```bash
VOUCH_RP_ID=auth.example.com
VOUCH_JWT_SECRET=<your-64-character-secret>
VOUCH_TLS_CERT=<base64-encoded-certificate>
VOUCH_TLS_KEY=<base64-encoded-private-key>
VOUCH_SSH_CA_KEY=<base64-encoded-ssh-ca-key>
```

Start:

```bash
docker compose up -d
docker compose logs -f vouch-server
```

## With PostgreSQL

```yaml
# docker-compose.yml
services:
  vouch-server:
    image: ghcr.io/vouch-sh/vouch:latest
    container_name: vouch-server
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    env_file:
      - vouch.env
    environment:
      VOUCH_DATABASE_URL: postgres://vouch:password@postgres:5432/vouch
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "--no-check-certificate", "https://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:16
    container_name: vouch-postgres
    restart: unless-stopped
    volumes:
      - postgres-data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: vouch
      POSTGRES_USER: vouch
      POSTGRES_PASSWORD: password
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vouch"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
```

## Air-Gapped Docker

For air-gapped environments, load the image from a saved archive:

```bash
# On connected machine
docker pull ghcr.io/vouch-sh/vouch:<version>
docker save ghcr.io/vouch-sh/vouch:<version> -o vouch-server-<version>.tar

# Transfer to air-gapped environment

# Load image
docker load < vouch-server-<version>.tar
```

## Upgrading

```bash
# Pull new image
docker compose pull

# Restart with new image
docker compose up -d

# Verify
docker compose logs -f vouch-server
curl -k https://auth.example.com/health
```
