# optimized_threat_int_engine
This is a custom built threat intelligence segregator and pool maker that can be accessed for IOC check and relative information retrieval using multi tech stack approach


Here is a comprehensive summary of the project based on your requirements:

**Project Overview: High-Performance Threat Intelligence Platform (TIP)**

This project involves architecting and building a scalable, high-throughput Threat Intelligence Platform designed to ingest, process, and serve intelligence from a massive, nested directory of mixed data (logs, raw files, and dumps). The core system is built using **Golang** for its concurrency and low memory footprint, utilizing a worker-pool pattern to recursively crawl directories and extract Indicators of Compromise (IOCs) like IPs, hashes, and domains using regex. To handle data at scale, the architecture employs a **tiered storage strategy**: standard IOCs are indexed in **ClickHouse** for rapid analytical querying, while "clean" or "miscellaneous" unstructured data is offloaded to **MinIO** object storage to prevent database bloat, with **Redis Bloom Filters** acting as a high-speed gating layer to instantly reject non-existent IOCs during searches. For advanced retrieval, **Qdrant** is integrated to handle vector-based "fuzzy" searches for domains or text. The system is exposed via a high-performance **REST API** that allows frontend clients to submit bulk IOC checks—receiving sub-millisecond verdicts via the Redis/ClickHouse pipeline—and request deep context by streaming original source files directly from MinIO when needed.
