# Build stage for frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Install build tools BEFORE npm install
# python3 is critical for node-gyp (used by many npm packages)
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    bash

# Copy and install dependencies
COPY frontend/package*.json ./
RUN npm install --verbose 2>&1 || npm install --verbose --legacy-peer-deps

# Copy source and build
COPY frontend/ ./
RUN npm run build


# Production stage
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install runtime dependencies
RUN apk add --no-cache \
    perl \
    wireshark-common \
    libffi \
    openssl

WORKDIR /app

# Copy requirements and install Python deps with build tools (virtual group)
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
