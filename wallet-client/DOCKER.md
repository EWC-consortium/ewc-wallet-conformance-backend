# Wallet Client Docker Setup

This document describes how to run the wallet-client service using Docker and Docker Compose.

## Quick Start

```bash
# Build and start the services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f wallet-client
```

## Services

### wallet-client
The main wallet service that handles credential issuance and presentation flows.

**Port:** 4000
**Health Check:** `GET /health`

### redis
Redis database for storing credentials and session data.

**Port:** 6379
**Password:** `wallet_redis_password`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 4000 | Server port |
| `NODE_ENV` | production | Node environment |
| `WALLET_REDIS` | redis:6379 | Redis connection string |
| `REDIS_PASSWORD` | wallet_redis_password | Redis password |
| `WALLET_CREDENTIAL_TTL` | 86400 | Credential storage TTL (seconds) |
| `WALLET_TEST_SESSION_TTL` | 86400 | Test session TTL (seconds) |
| `WALLET_DEBUG_CREDENTIAL` | false | Enable full credential logging |
| `WALLET_MDL_STRICT` | false | Enable strict MDL verification |
| `WALLET_POLL_TIMEOUT_MS` | 30000 | Deferred credential polling timeout |
| `WALLET_POLL_INTERVAL_MS` | 2000 | Deferred credential polling interval |

## Usage Examples

### Start services
```bash
docker-compose up -d
```

### Stop services
```bash
docker-compose down
```

### Rebuild and restart
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### View logs
```bash
# All services
docker-compose logs -f

# Wallet client only
docker-compose logs -f wallet-client

# Redis only
docker-compose logs -f redis
```

### Access the service
```bash
# Health check
curl http://localhost:4000/health

# Issue credentials
curl -X POST http://localhost:4000/issue \
  -H "Content-Type: application/json" \
  -d '{"issuer": "http://your-issuer.com", "offer": "openid-credential-offer://..."}'
```

## Volumes

- `redis-data`: Persistent Redis data storage
- `./keys:/app/keys:ro`: Read-only mount for key files (optional)

## Networks

- `wallet-network`: Internal network for service communication

## Security Notes

- The wallet-client runs as a non-root user
- Redis is configured with password authentication
- Health checks are enabled for both services
- Services restart automatically unless explicitly stopped

## Troubleshooting

### Service won't start
```bash
# Check logs
docker-compose logs wallet-client

# Check if Redis is healthy
docker-compose exec redis redis-cli ping
```

### Redis connection issues
```bash
# Test Redis connection
docker-compose exec wallet-client node -e "
const redis = require('redis');
const client = redis.createClient({url: 'redis://redis:6379', password: 'wallet_redis_password'});
client.connect().then(() => console.log('Redis connected')).catch(console.error);
"
```

### Port conflicts
If port 4000 or 6379 are already in use, modify the `docker-compose.yml` file to use different ports:

```yaml
ports:
  - "4001:4000"  # Map host port 4001 to container port 4000
```
