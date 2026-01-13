# Ubuntu VM Setup Guide

This document covers everything you need to do on your Ubuntu VM to run the Threat Intelligence Platform.

---

## Prerequisites

### 1. Install Docker & Docker Compose
```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group (logout/login after)
sudo usermod -aG docker $USER

# Install Docker Compose plugin
sudo apt install docker-compose-plugin -y

# Verify installation
docker --version
docker compose version
```

### 2. Install Go (for running/building ingestor)
```bash
# Download Go 1.23 (latest stable)
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz

# Extract to /usr/local
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz

# Add to PATH (add to ~/.bashrc for persistence)
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
```

---

## VM Directory Structure

```
/home/<user>/
├── tip-server/              # Clone/copy the project here
│   ├── cmd/
│   ├── internal/
│   ├── docker-compose.yml
│   └── ...
├── threat-data/             # Your nested data folder (READ-ONLY source)
│   ├── logs/
│   ├── dumps/
│   ├── samples/
│   └── ...                  # Nested mixed data to be crawled
└── .env                     # Environment variables
```

---

## Environment Variables (.env)

Create `/home/<user>/tip-server/.env`:

```bash
# === Data Source ===
DATA_PATH=/home/<user>/threat-data    # Path to your nested data folder

# === ClickHouse ===
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=9000
CLICKHOUSE_DATABASE=threat_intel
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

# === Redis ===
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# === MinIO ===
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=admin
MINIO_SECRET_KEY=SuperSecretPassword123
MINIO_BUCKET=misc-data
MINIO_USE_SSL=false

# === Qdrant (Phase 2) ===
QDRANT_HOST=localhost
QDRANT_PORT=6334

# === API Server ===
API_PORT=8080
API_KEY=your-secure-api-key-here

# === Worker Settings ===
WORKER_COUNT=50
BATCH_SIZE=1000
```

---

## Step-by-Step VM Tasks

### Step 1: Start Docker Services
```bash
cd ~/tip-server
docker compose up -d

# Verify all containers are running
docker compose ps

# Expected output:
# clickhouse   running   0.0.0.0:8123->8123/tcp, 0.0.0.0:9000->9000/tcp
# redis        running   0.0.0.0:6379->6379/tcp
# minio        running   0.0.0.0:9000->9000/tcp, 0.0.0.0:9001->9001/tcp
# qdrant       running   0.0.0.0:6333->6333/tcp, 0.0.0.0:6334->6334/tcp
```

### Step 2: Initialize MinIO Bucket
```bash
# Access MinIO Console at http://<vm-ip>:9001
# Login: admin / SuperSecretPassword123
# Create bucket: misc-data

# Or via CLI:
docker exec -it <minio-container> mc alias set local http://localhost:9000 admin SuperSecretPassword123
docker exec -it <minio-container> mc mb local/misc-data
```

### Step 3: Verify ClickHouse Schema
```bash
# Connect to ClickHouse
docker exec -it <clickhouse-container> clickhouse-client

# Check tables exist
SHOW TABLES FROM threat_intel;
# Expected: file_registry, ioc_store

# Exit
exit
```

### Step 4: Run the Ingestor
```bash
cd ~/tip-server

# First run (will take time depending on data size)
go run cmd/ingestor/main.go

# Or build and run binary
go build -o ingestor cmd/ingestor/main.go
./ingestor
```

### Step 5: Start the API Server
```bash
cd ~/tip-server

# Run in background with nohup
nohup go run cmd/api/main.go > api.log 2>&1 &

# Or build and run as service (recommended for production)
go build -o api-server cmd/api/main.go
./api-server
```

---

## Firewall Rules (if needed)

```bash
# Allow API access from outside VM
sudo ufw allow 8080/tcp    # API Server

# Optional: Allow direct access to services (not recommended for production)
sudo ufw allow 8123/tcp    # ClickHouse HTTP
sudo ufw allow 6379/tcp    # Redis
sudo ufw allow 9001/tcp    # MinIO Console
```

---

## Monitoring Commands

```bash
# Check ingestor progress
tail -f ~/tip-server/ingestor.log

# Check API logs
tail -f ~/tip-server/api.log

# Monitor Docker resource usage
docker stats

# Check ClickHouse IOC count
docker exec -it <clickhouse-container> clickhouse-client \
  --query "SELECT ioc_type, count() FROM threat_intel.ioc_store GROUP BY ioc_type"

# Check file processing status
docker exec -it <clickhouse-container> clickhouse-client \
  --query "SELECT scan_status, count() FROM threat_intel.file_registry GROUP BY scan_status"

# Check Redis Bloom Filter info
docker exec -it <redis-container> redis-cli BF.INFO ioc_bloom
```

---

## Quick Test Commands

```bash
# Test API health
curl http://localhost:8080/health

# Test IOC check (replace with your API key)
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secure-api-key-here" \
  -d '{"iocs": ["8.8.8.8", "malware.com"]}'

# Test context retrieval
curl http://localhost:8080/context/<file_id> \
  -H "X-API-Key: your-secure-api-key-here" \
  --output context.txt
```

---

## Checklist

```
[ ] Docker & Docker Compose installed
[ ] Go 1.23+ installed
[ ] Project files copied to ~/tip-server
[ ] .env file configured with correct DATA_PATH
[ ] docker compose up -d (all services running)
[ ] MinIO bucket 'misc-data' created
[ ] ClickHouse schema verified
[ ] Ingestor run completed
[ ] API server running
[ ] API tested with curl
```
