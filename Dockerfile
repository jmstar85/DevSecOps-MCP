# DevSecOps MCP Server Docker Image
FROM node:18-alpine AS base

# Install security tools and dependencies
RUN apk add --no-cache \
    git \
    curl \
    wget \
    python3 \
    py3-pip \
    openjdk11-jre \
    docker-cli \
    bash \
    jq \
    && rm -rf /var/cache/apk/*

# Install security tools
RUN pip3 install --no-cache-dir \
    semgrep \
    checkov \
    bandit \
    safety

# Install OSV Scanner
RUN wget -qO- https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64.tar.gz | tar -xz -C /usr/local/bin

# Install Trivy
RUN wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Development stage
FROM base AS development
RUN npm ci && npm cache clean --force
COPY . .
RUN npm run build
CMD ["npm", "run", "dev"]

# Production stage
FROM base AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mcp -u 1001 -G nodejs

# Copy built application
COPY --from=development --chown=mcp:nodejs /app/dist ./dist
COPY --from=development --chown=mcp:nodejs /app/node_modules ./node_modules
COPY --from=development --chown=mcp:nodejs /app/src/config ./src/config
COPY --from=development --chown=mcp:nodejs /app/package.json ./

# Create directories for security tools data
RUN mkdir -p /app/security-reports /app/logs /tmp/trivy-cache /tmp/osv-db && \
    chown -R mcp:nodejs /app /tmp/trivy-cache /tmp/osv-db

# Install git-secrets
RUN git clone https://github.com/awslabs/git-secrets.git /tmp/git-secrets && \
    cd /tmp/git-secrets && \
    make install && \
    rm -rf /tmp/git-secrets

# Security: Remove unnecessary packages and files
RUN apk del wget && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Switch to non-root user
USER mcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "const http = require('http'); \
    const options = { hostname: 'localhost', port: 3000, path: '/health', method: 'GET' }; \
    const req = http.request(options, (res) => { \
        if (res.statusCode === 200) { process.exit(0); } else { process.exit(1); } \
    }); \
    req.on('error', () => { process.exit(1); }); \
    req.end();" || exit 1

# Expose port
EXPOSE 3000

# Environment variables
ENV NODE_ENV=production \
    MCP_PORT=3000 \
    LOG_LEVEL=info \
    SECURITY_STRICT_MODE=true

# Start the application
CMD ["node", "dist/src/mcp/server.js"]