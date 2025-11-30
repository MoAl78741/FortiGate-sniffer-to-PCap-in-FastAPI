# Build stage for frontend - use FULL node image, not alpine
FROM node:22.16.0 AS frontend-builder

WORKDIR /app/frontend

# Set memory limit for Node to avoid OOM kills
ENV NODE_OPTIONS="--max-old-space-size=2048"

# Copy and install dependencies
COPY frontend/package*.json ./

# Use npm ci (faster, respects lock file exactly)
RUN npm ci --no-audit --no-fund

# Copy source and build
COPY frontend/ ./
RUN npm run build


# Production stage - alpine for smaller final image
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install wget for health checks
RUN apk add --no-cache wget

WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt .

RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy application code and built frontend
COPY fastapi_app/ ./fastapi_app/
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/docs || exit 1

CMD ["uvicorn", "fastapi_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
