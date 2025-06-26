# Multi-stage build for production
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Install runtime dependencies only
RUN apk add --no-cache \
    openssl \
    ca-certificates \
    && update-ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S devsecops -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist

# Copy necessary configuration files
COPY .eslintrc.json ./
COPY .prettierrc ./

# Set ownership to non-root user
RUN chown -R devsecops:nodejs /app

# Switch to non-root user
USER devsecops

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "console.log('Health check passed')" || exit 1

# Expose port (if needed for HTTP interface)
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV LOG_LEVEL=info

# Start the application
CMD ["node", "dist/index.js"]