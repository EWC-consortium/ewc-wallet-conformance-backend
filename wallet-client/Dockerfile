FROM node:20-slim

# Install necessary packages for crypto operations
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first for better caching
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install --omit=dev && npm cache clean --force

# Copy source code
COPY src ./src

# Copy utils directory
COPY utils ./utils

# Copy key/cert and DID materials required at runtime
COPY didjwks ./didjwks
COPY x509EC ./x509EC
COPY x509 ./x509
COPY X25519 ./X25519

# Create non-root user for security
RUN groupadd -r wallet && useradd -r -g wallet wallet
RUN chown -R wallet:wallet /app
USER wallet

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

EXPOSE 4000

CMD ["node", "src/server.js"]


