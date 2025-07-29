# Multi-stage Docker build for NestJS Auth Service
# Stage 1: Build stage with dependencies and build tools
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Install pnpm globally for better performance
RUN npm install -g pnpm@latest

# Copy package files for dependency resolution
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY nx.json tsconfig.base.json ./

# Copy all project files for Nx workspace
COPY apps/ apps/
COPY libs/ libs/

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build the auth-service application
RUN pnpm nx build auth-service --prod

# Stage 2: Production runtime stage
FROM node:20-alpine AS runtime

# Install security updates and essential packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    ca-certificates \
    curl \
    dumb-init \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1001 -S nestjs && \
    adduser -S nestjs -u 1001 -G nestjs

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=nestjs:nestjs /app/dist/auth-service ./
COPY --from=builder --chown=nestjs:nestjs /app/node_modules ./node_modules

# Copy essential config files
COPY --chown=nestjs:nestjs package.json ./

# Create directory for logs and uploads
RUN mkdir -p /app/logs /app/uploads && \
    chown -R nestjs:nestjs /app/logs /app/uploads

# Switch to non-root user
USER nestjs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-3000}/health || exit 1

# Expose port
EXPOSE 3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "main.js"]