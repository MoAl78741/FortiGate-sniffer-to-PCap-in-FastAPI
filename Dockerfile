# Build stage for frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend source
COPY frontend/package*.json ./
RUN npm install --verbose

COPY frontend/ ./
RUN npm run build


# Production stage
FROM python:3.12-alpine

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install runtime dependencies
# - perl: required for text2pcap
# - wireshark-common: provides text2pcap for pcap conversion
# - libffi & openssl: required for cryptography (used by python-jose)
RUN apk add --no-cache \
    perl \
    wireshark-common \
    libffi \
    openssl

# Install build dependencies, install Python packages, then remove build deps
WORKDIR /app

COPY requirements.txt .

RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# Create non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy application code
COPY fastapi_app/ ./fastapi_app/

# Copy built frontend from builder stage
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Create data directory for database persistence
RUN mkdir -p /app/data

# Set ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/docs || exit 1

# Run the application with uvicorn
CMD ["uvicorn", "fastapi_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
