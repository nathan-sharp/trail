# TRAIL (Text Retrieval & Automated Indexing Library)

TRAIL is a self-hosted web crawler, Full-Text Search Version 5 (FTS5) indexer, Best Matching 25 (BM25) query engine, and HyperText Markup Language (HTML) 2.0 web server. TRAIL operates on a Raspberry Pi 4 or 5 with an external Universal Serial Bus (USB) Hard Disk Drive (HDD).

## System Architecture

| Component | Technology | Role |
| :--- | :--- | :--- |
| Zero-Touch USB Provisioner | Python 3.12 (`trail/disk.py`, `trail/main.py`) | Auto-detects non-boot USB disks with capacity $\ge 500\text{ gigabytes (GB)}$ ($5.0 \times 10^{11}\text{ bytes}$), excludes `/dev/mmcblk*` and the Operating System (OS) root disk, formats uninitialized drives as `ext4` with label `TRAIL_DATA`, mounts the volume, assigns User Identifier (UID) `10001` ownership, and irreversibly drops root privileges to `UID 10001`. |
| Crawler Engine | Python 3.12 (`trail/crawler.py`) | Performs open-hop crawling, enforces Request for Comments (RFC) 9309 `robots.txt`, and blocks Server-Side Request Forgery (SSRF). |
| Storage and Index | SQLite 3 FTS5 (`trail/storage.py`) | Stores documents in Write-Ahead Logging (WAL) mode with a $64\text{ megabyte (MB)}$ page cache and ranks queries via BM25. |
| Web and OpenSearch Server | Python 3.12 (`trail/server.py`) | Serves RFC 1866 HTML 2.0 responses (zero Cascading Style Sheets (CSS), zero JavaScript (JS)) and OpenSearch 1.1 Extensible Markup Language (XML). |
| Ingress Tunnel | `cloudflare/cloudflared` | Exposes port `8080` to a public domain without inbound router port forwarding. |

## Single-Command Deployment Procedure

### Prerequisites
- Hardware: Raspberry Pi 4 or 5 with $4\text{ GB}$ or $8\text{ GB}$ Random Access Memory (RAM) and an external USB drive with capacity $\ge 500\text{ GB}$ (such as a $2\text{ terabyte (TB)}$ USB HDD).
- Operating System: 64-bit Linux (`aarch64` / `arm64`).
- Required Tools: Docker Engine 24.0 or newer and Docker Compose v2.20 or newer.
- Assumptions: The external USB drive is plugged into a Raspberry Pi USB port.
- Warning (Automatic Initial Formatting): On initial startup (`TRAIL_AUTO_FORMAT=true`), TRAIL automatically formats the detected non-boot USB drive ($\ge 500\text{ GB}$) as `ext4` with filesystem label `TRAIL_DATA` if it does not yet carry the `TRAIL_DATA` label. On all subsequent startups, TRAIL recognizes the `TRAIL_DATA` label and mounts the drive without formatting.
- Warning (Supply Chain and Dependency Security): Verify the cryptographic digest and publisher authenticity of the `python:3.12-slim-bookworm` and `cloudflare/cloudflared:2024.11.1` container images on Docker Hub before deployment.
- Warning (Legacy Client Transport Layer Security (TLS) Compatibility): Cloudflare forces TLS 1.2 or TLS 1.3 on HyperText Transfer Protocol Secure (HTTPS) endpoints. Native Windows 95 and Netscape Navigator 2.0 clients lack TLS 1.2 ciphers and must connect over plain HyperText Transfer Protocol (HTTP) on port `8080` across the local network.

### Action Steps
1. Copy `.env.example` to `.env` in the project directory:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` to set `TRAIL_BASE_URL` and `CLOUDFLARE_TUNNEL_TOKEN` (and optional `TRAIL_USB_DEVICE` override).
3. Edit `config/seeds.txt` and list one starting HTTP or HTTPS Uniform Resource Locator (URL) per line.
4. Deploy the entire system (including automatic USB drive formatting and mounting) with one command:
   ```bash
   docker compose up -d --build
   ```
5. Verify container health status via the `/healthz` endpoint:
   ```bash
   curl http://127.0.0.1:8080/healthz
   ```

## Verification and Testing

Run the Institute of Electrical and Electronics Engineers (IEEE) 29119 unit test suite with the command below:

```bash
python -m unittest discover -s tests -v
```
