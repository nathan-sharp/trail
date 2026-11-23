# TRAIL (Text Retrieval & Automated Indexing Library)

TRAIL (`v2026`) is a self-hosted web crawler, Full-Text Search Version 5 (FTS5) indexer, Best Matching 25 (BM25) query engine, and HyperText Markup Language (HTML) 2.0 web server for a Raspberry Pi 4 or 5 with an external Universal Serial Bus (USB) Hard Disk Drive (HDD).

---

## 1. Quick Start (3 Steps)

### Prerequisites and Warnings
- **Hardware**: Raspberry Pi 4 or 5 ($4\text{ gigabytes (GB)}$ or $8\text{ GB}$ Random Access Memory (RAM)) running 64-bit Raspberry Pi Operating System (OS) (`arm64`) with a USB drive $\ge 500\text{ GB}$ (such as a $2\text{ terabyte (TB)}$ USB HDD).
- **Required Tools**: Secure Shell (SSH) access and `curl`.
- **Assumptions**: Only one non-boot USB drive $\ge 500\text{ GB}$ is plugged in during initial setup.
- **Warning (Automatic Disk Formatting)**: On first boot, TRAIL formats the detected non-boot USB drive ($\ge 500\text{ GB}$) as `ext4` (`LABEL=TRAIL_DATA`) if unlabeled, erasing prior data on that USB drive.
- **Warning (Supply-Chain Verification)**: Inspect `install.sh` (`curl -fsSL https://raw.githubusercontent.com/nathan-sharp/trail/main/install.sh | less`) and verify container image digests (`python:3.12-slim-bookworm`, `cloudflare/cloudflared`) before execution.
- **Warning (Windows 95 / Netscape Transport Layer Security (TLS))**: Cloudflare enforces TLS 1.2/1.3 on public HyperText Transfer Protocol Secure (HTTPS) domains. Connect legacy browsers over your Local Area Network (LAN) via plain HyperText Transfer Protocol (HTTP) at `http://<raspberry-pi-ip>:8080/`.

### Setup Steps
1. Plug the $2\text{ TB}$ USB drive into a blue USB 3.0 port on the Raspberry Pi.
2. In the Cloudflare Zero Trust tunnel setup screen, click the **Copy** button on the **Run tunnel with Docker** box (not the **Tunnel ID** box), and route your public hostname to `http://trail:8080`.
3. Run the one-line installer on the Raspberry Pi terminal and paste either the copied **Run tunnel with Docker** command or the `eyJ...` token when prompted:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/nathan-sharp/trail/main/install.sh | sudo bash
   ```

*(Optional non-interactive one-liner using the `eyJ...` token from the end of the "Run tunnel with Docker" box)*:
```bash
curl -fsSL https://raw.githubusercontent.com/nathan-sharp/trail/main/install.sh | sudo bash -s -- https://search.njs.dev eyJhIjoi...
```

---

## 2. What the Installer Automates

| Stage | Automated Action |
| :--- | :--- |
| **1. Host Packages** | Installs `git`, `curl`, `ca-certificates`, Docker Engine, and Docker Compose if missing. |
| **2. Repository & Config** | Clones `https://github.com/nathan-sharp/trail.git` to `/opt/trail`, extracts the `eyJ...` token even if you paste the full `docker run ...` string, and writes `/opt/trail/.env` with mode `0600`. |
| **3. USB Drive Setup** | Detects the non-boot USB disk $\ge 500\text{ GB}$ ($5.0 \times 10^{11}\text{ bytes}$), creates a GUID Partition Table (GPT), formats as `ext4` (`LABEL=TRAIL_DATA`) on first boot, mounts `/app/data`, and drops process privileges to User Identifier (UID) `10001`. |
| **4. Search & Tunnel** | Starts the Request for Comments (RFC) 1866 HTML 2.0 server, OpenSearch 1.1 Extensible Markup Language (XML) endpoint (`/opensearch.xml`), open-hop crawler, and Cloudflare Tunnel. |
| **5. Auto-Updater** | Audits International Organization for Standardization (ISO) Timestamp Versioning (https://njs.dev/other/versioning/) and Debian packages every $21\,600\text{ seconds (s)}$ ($6\text{ hours (h)}$) and applies updates automatically. |

---

## 3. Common Operations

| Action | Command or Uniform Resource Locator (URL) |
| :--- | :--- |
| **Force an immediate system update** | `trail-update` (or `curl -fsSL https://raw.githubusercontent.com/nathan-sharp/trail/main/install.sh \| sudo bash`) |
| **Edit crawled seed websites** | `sudo nano /opt/trail/config/seeds.txt` (reloads automatically every $30\text{ s}$) |
| **View system and index status** | Open `http://<raspberry-pi-ip>:8080/status` |
| **Add as default browser search** | Open your TRAIL URL and select **Add "TRAIL Search"** in the browser address bar |
| **View container logs** | `sudo docker logs -f trail-server` |
| **Run unit test suite (21 tests)** | `python3 -m unittest discover -s tests -v` |
