# Optimized Threat Intelligence Ingestion Engine (TIP)

A high-throughput Threat Intelligence Platform built in **Go** to ingest heterogeneous datasets, extract **Indicators of Compromise (IOCs)**, and serve ultra-fast IOC lookups and contextual evidence retrieval.

This project was **validated on ~25GB of heterogeneous data**, converting it into a structured dataset of **~50 million IOC rows** (IPs, hashes, domains, URLs, and other misc artifacts) with **Qdrant** used for storing/searching additional miscellaneous or semantic-friendly content.

---

## Key Capabilities

### 1) High-Speed IOC Extraction at Scale
- Recursively crawls large, nested directory trees.
- Extracts common IOC types using compiled patterns / structured parsing:
  - IPv4 / IPv6
  - Domains
  - URLs
  - Hashes (e.g., MD5, SHA256)
  - (Extensible for more IOC types)

### 2) Change Detection / Idempotent Processing
- Avoids re-processing files that have not changed since the last run by comparing file metadata (e.g., modification time) with the registry stored in the database.
- Deterministic file identity (stable `file_id`) enables repeatable ingestion runs.

### 3) Tiered Storage Architecture (Built for Cost + Performance)
This platform intentionally separates **index/search data** from **raw file context**:

- **ClickHouse**: primary structured store for IOCs and file registry metadata (optimized for massive-scale insert + analytics queries).
- **Redis Bloom Filter** (Redis Stack): a high-speed “gating layer” to reject non-existent IOCs in sub-millisecond time before hitting ClickHouse.
- **MinIO**: object storage for raw “miscellaneous / non-IOC” files (and evidence/context blobs) to prevent database bloat.
- **Qdrant**: optional vector/semantic-friendly store for fuzzy/approx search and storing additional extracted/derived artifacts.

### 4) Worker-Pool Ingestion (Concurrency-Optimized)
- Uses a Go worker-pool model to parallelize file processing across many goroutines.
- Designed to sustain continuous ingestion throughput with low memory overhead.
- Performs batch insertions to ClickHouse for efficiency.

### 5) Fast IOC Lookup API (Operational Usage)
A Go HTTP API (Fiber-based per design) to support:
- **Bulk IOC checks** (e.g., “are these 10,000 indicators known?”)
- **Context retrieval** by `file_id` (stream raw evidence from MinIO when needed)

Core lookup strategy:
1. Check IOC existence via **Redis Bloom** (fast negative filtering).
2. Query **ClickHouse** only for likely hits.
3. Return verdict + source metadata.

### 6) Metrics & Observability Hooks
The ingestion flow records operational signals such as:
- Files scanned / skipped
- IOCs extracted by type
- Insert and processing timings
- Error counts

(Exact metrics coverage depends on configuration and runtime wiring.)

---

## Architecture Overview

### Pipeline Summary
1. **Ingestion (Go worker pool)**
   - Walk directory, identify changed/new files, extract IOCs.
2. **Segregation**
   - If IOCs found → store in **ClickHouse** and add to **Redis Bloom**.
   - If no IOCs / miscellaneous → upload raw content to **MinIO** and store metadata in ClickHouse.
3. **Access**
   - API checks **Redis Bloom** first, then **ClickHouse** for confirmed hits.
   - API can stream raw context from **MinIO** for investigations.

This design is documented in `Pipeline.md` and implemented in `tip-server/`.

---

## Repository Layout (High-Level)

Typical structure:
- `Pipeline.md` — Master implementation guide / architecture spec
- `docker-compose.yml` — local infra (ClickHouse, Redis Stack, MinIO, Qdrant)
- `init-db/` — ClickHouse schema init
- `tip-server/`
  - `cmd/ingestor/` — directory crawler + extractor (worker pool)
  - `cmd/api/` — REST API server
  - `internal/`
    - `db/` — ClickHouse/Redis/MinIO/Qdrant clients and wrappers
    - `extractor/` — IOC scanning/extraction logic
    - `models/` — shared types (IOC, file metadata, results)
    - `config/` — configuration loading
    - `metrics/` — ingestion metrics

---

## Data Model (Conceptual)

### File Registry
Tracks ingestion state and ties outputs back to the original file.
- `file_id` (stable hash of file path or deterministic identifier)
- `file_path`
- `last_modified`
- `scan_status` (e.g., pending/clean/infected/misc/failed)
- `minio_key` (when stored as object)
- `processed_at`

### IOC Store
Stores the searchable IOC index:
- `ioc_value`
- `ioc_type` (ipv4/ipv6/domain/url/md5/sha256/…)
- `source_file_id`
- Additional enrichment fields (confidence, malware_family, timestamps, etc.)

---

## Running Locally (Typical)

### 1) Start Infrastructure
```bash
docker-compose up -d
```

### 2) Initialize Databases
If using ClickHouse init scripts, schema setup can be automatic via mounted init files.
Otherwise, apply the SQL from `init-db/` (see `Pipeline.md` for schema guidance).

### 3) Run the Ingestor
```bash
go run tip-server/cmd/ingestor/main.go
```
Point it at your target dataset directory via config/env flags (see `internal/config`).

### 4) Start the API
```bash
go run tip-server/cmd/api/main.go
```

---

## API (Conceptual)

### `POST /check`
Bulk check IOCs.
- Request:
```json
{ "iocs": ["1.2.3.4", "bad-domain.com", "…"] }
```

- Behavior:
  1. Bloom filter existence checks (fast filter)
  2. ClickHouse lookup for probable hits
  3. Returns verdict + source references

### `GET /context/:file_id`
Retrieve source context for investigation.
- Looks up metadata in ClickHouse
- Streams raw content from MinIO

(Exact routes and response shapes depend on the current implementation in `cmd/api`.)

---

## Performance Notes

- Designed for **very large, messy real-world datasets** (logs, dumps, unstructured files).
- Proven pipeline outcome in testing:
  - **~25GB heterogeneous input**
  - **~50 million structured IOC rows** (IPs, hashes, domains, URLs, etc.)
  - Miscellaneous and semantic-friendly artifacts stored in **Qdrant**

---

## Extending the System

Common extensions:
- Add more IOC patterns (CVE IDs, emails, filenames, mutexes, registry keys, BTC wallets, etc.)
- Add normalization (punycode domains, URL canonicalization, hash validation)
- Add enrichment (WHOIS, GeoIP, ASN, threat feeds)
- Add deduplication / confidence scoring rules
- Add distributed ingestion (multi-node workers)

---

## Security & Operational Considerations

- Treat ingested data as potentially malicious.
- Run ingestion in isolated environments.
- Restrict MinIO/Qdrant/ClickHouse exposure (network policies, auth, secrets management).
- Consider encryption-at-rest and auditing for regulated environments.

---

## License
Add a license file if you plan to distribute or open-source this project.
