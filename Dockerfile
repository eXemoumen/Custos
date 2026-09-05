# Custos Control Plane - All-in-One Container
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy package sources
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install Custos with server and YAML dependencies
RUN pip install --no-cache-dir \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.28" \
    "websockets>=12.0" \
    "pyyaml>=6.0" \
    "jsonschema>=4.21" \
    && pip install --no-cache-dir -e .

# Create storage directory for audit logs and knowledge base
RUN mkdir -p /root/.custos

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV CUSTOS_HOST="0.0.0.0"
ENV CUSTOS_PORT="8000"

CMD ["custos", "serve", "--host", "0.0.0.0", "--port", "8000"]
