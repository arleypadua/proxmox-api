# Proxmox Telemetry & Configuration Broker API

A lightweight, zero-dependency, read-only telemetry and configuration broker API built specifically for Proxmox VE hosts. Statically compiled and using exclusively the Go Standard Library, it provides a safe, low-overhead interface for autonomous AI agents like **Hermes** to inspect hypervisor health, read container settings, and parse configurations.

---

## Technical Overview

- **Zero Runtime Dependencies:** Built strictly using Go standard packages (`net/http`, `os`, `os/exec`, `syscall`, `crypto/rand`, etc.). Compiles into a single statically linked binary with a negligible footprint.
- **Stateful Config Lifecycle:** On startup, the application resolves the host home directory (`~`) and checks for `~/.proxmox-api/.env`. If the folder or file is missing, it is created automatically. A secure 24-byte hex key is generated via `crypto/rand` and loaded into the environment along with binding defaults.
- **Security & Authorization:** Enforces header-based authentication via `X-API-Key` validation middleware across all telemetry and container paths.
- **Self-Hosted Documentation:** Serves interactive Swagger API docs locally via `GET /docs` and raw OpenAPI definitions via `GET /swagger.json` without any local static asset file requirements.
- **Double-Sampled Host CPU:** Samples `/proc/stat` twice with a 200ms sleep delta to calculate exact, real-time CPU utilization.
- **LXC Integration:** Directly executes standard Proxmox container tools (`pct list`, `pct status --verbose`) and reads configurations (`/etc/pve/lxc/*.conf`) under root permissions.
- **Automatic Mock Fallback:** Detects if it is running in a non-Proxmox environment (e.g. developer macOS or generic Linux hosts where `pct` is missing) and automatically switches to **Mock Mode**, serving realistic home lab statistics for offline development and testing.

---

## Interactive API Documentation

Once started, point your browser to:
```text
http://<host-ip>:8000/docs
```
It renders a sleek dark-themed Swagger UI sandbox. The OpenAPI specification is also served at `/swagger.json` to enable automated tool mapping for client agents.

---

## Running the API

You can run the API either for local development/testing or in production on your Proxmox host.

### 1. Running Locally (Development / Mock Mode)
When running on macOS or standard Linux machines without the Proxmox `pct` utility, the API automatically falls back to **Mock Mode**.
1. **Start the API:**
   ```bash
   ./proxmox-api
   ```
2. **Review Config Banner:** On initial startup, the API creates a `.env` file in the current repository folder, generates a randomized `HERMES_API_KEY`, and prints a setup banner:
   ```text
   ======================================================================
     PROXMOX API BROKER - CONFIGURATION STATUS
   ======================================================================
     Config file path: .env
     Active settings:
     HERMES_API_KEY = your_generated_hex_key_here
     BIND_IP        = 0.0.0.0
     BIND_PORT      = 8000
   ======================================================================
   ```
3. **Customize Config:** You can edit the local `.env` file to change the port or specify an explicit key.
4. **Access UI:** Open `http://localhost:8000/docs` in your browser to inspect or test the endpoints.

### 2. Running in Production (Proxmox VE Host)
In production, the API must run with root privileges to execute Proxmox CLI tools (`pct`) and read container configuration files from `/etc/pve/lxc/`.
- **Manual Start:**
  ```bash
  sudo ./proxmox-api
  ```
- **Systemd Start:** Run the broker via the systemd service (see guide below).

---

## Automated Deployment Guide (Systemd)

Save the following Bash script as `install.sh`, make it executable, and run it as `root` on your Proxmox VE host. The script pulls the compiled binary, installs it, configures systemd, starts the daemon, and registers boot-time execution.

```bash
#!/usr/bin/env bash
#
# Proxmox API Broker - Installation & Deployment Script
# Automatically deploys the broker as a systemd service.
# Run this script as root on the Proxmox VE host.

set -euo pipefail

# Configuration
VERSION="latest" # Change to target tag version or keep "latest"
GITHUB_REPO="arleypadua/proxmox-api"
BINARY_NAME="proxmox-api"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
SYSTEMD_SERVICE="/etc/systemd/system/${BINARY_NAME}.service"

echo "=== Proxmox API Broker Installer ==="

# 1. Check Root Privileges
if [[ $EUID -ne 0 ]]; then
   echo "Error: This installer must be run as root." >&2
   exit 1
fi

# 2. Stop Service if Running (Prevent 'Text File Busy' Errors)
if systemctl is-active --quiet "${BINARY_NAME}.service"; then
    echo "Stopping existing ${BINARY_NAME} service for upgrade..."
    systemctl stop "${BINARY_NAME}.service"
fi

# 3. Download Precompiled Binary
if [[ "${VERSION}" == "latest" ]]; then
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}"
else
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}"
fi

echo "Downloading ${BINARY_NAME} (${VERSION})..."
if curl -sSfL -o "${INSTALL_PATH}" "${DOWNLOAD_URL}"; then
    echo "Download completed successfully."
else
    echo "Download failed. Please check the version/repo configuration." >&2
    exit 1
fi

# 4. Configure Binary Permissions
chmod 0755 "${INSTALL_PATH}"
chown root:root "${INSTALL_PATH}"
echo "Installed binary to ${INSTALL_PATH}."

# 5. Generate Systemd Service Configuration
echo "Generating systemd service configuration..."
cat <<EOF > "${SYSTEMD_SERVICE}"
[Unit]
Description=Proxmox Telemetry and Configuration Broker API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=${INSTALL_PATH}
Restart=on-failure
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 6. Reload Daemon and Start Service
echo "Activating systemd service..."
systemctl daemon-reload
systemctl enable "${BINARY_NAME}.service"
systemctl restart "${BINARY_NAME}.service"

echo "=== Installation Completed Successfully! ==="
echo "Check credentials and startup logs with:"
echo "  journalctl -u ${BINARY_NAME} -n 25 --no-pager"
```

---

## Verification & Monitoring

### Inspecting Setup Logs & API Keys
When the service runs for the first time, it generates the API key and configuration file. Inspect the startup console output:
```bash
journalctl -u proxmox-api --no-pager
```

This outputs a prominent status banner showing:
```text
======================================================================
  PROXMOX API BROKER - CONFIGURATION STATUS
======================================================================
  Config file path: /root/.proxmox-api/.env

  Active settings:
  ------------------------------------------------------------------
  HERMES_API_KEY = c3f28d84a780db0c7e2a9b40...
  BIND_IP        = 0.0.0.0
  BIND_PORT      = 8000
  ------------------------------------------------------------------

  SECURITY DETAILS:
  Authenticate headers for incoming Hermes Agent requests using:
  X-API-Key: c3f28d84a780db0c7e2a9b40...

  Interactive API documentation sandbox is accessible at:
  http://localhost:8000/docs
======================================================================
```

### Manual API Testing
Export your key and test query endpoints using `curl`:

```bash
# Retrieve the generated key from the configuration file
API_KEY=$(grep HERMES_API_KEY /root/.proxmox-api/.env | cut -d'=' -f2)

# Query Host and Basic Container Telemetry
curl -H "X-API-Key: ${API_KEY}" http://localhost:8000/api/v1/telemetry

# Query Detailed Cluster Containers
curl -H "X-API-Key: ${API_KEY}" http://localhost:8000/api/v1/containers

# Query Container Configuration File
curl -H "X-API-Key: ${API_KEY}" "http://localhost:8000/api/v1/container/config?vmid=100"
```

---

## Building from Source

Because this broker is designed with zero external runtime package dependencies, compiling it is straightforward on any system with Go installed.

### Prerequisites
- Go compiler version **1.21 or higher**.

### Local Development Build
To compile a binary quickly for your current OS and CPU architecture (e.g. testing locally on macOS/Windows/Linux):
```bash
go build -o proxmox-api main.go
```

### Apple Silicon macOS (M1/M2/M3) Build
To build specifically for Apple Silicon macOS (darwin/arm64):
```bash
GOOS=darwin GOARCH=arm64 go build -o proxmox-api main.go
```

> [!IMPORTANT]
> **Troubleshooting: `zsh: exec format error: ./proxmox-api`**
> This error indicates you are trying to execute a binary compiled for a different system (e.g., trying to run the production Linux AMD64 binary on your Mac). Be sure to build using `go build` or specify the `GOOS=darwin GOARCH=arm64` environment variables for Apple Silicon local execution.

### Production Build (Statically Linked Linux AMD64)
To build a size-optimized, statically linked binary targeting the Proxmox VE host (Linux AMD64), run:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o proxmox-api main.go
```

**Compiler Flags Breakdown:**
- `CGO_ENABLED=0`: Disables dynamic linking against glibc, resulting in a fully self-contained static binary that runs on any Linux host.
- `GOOS=linux GOARCH=amd64`: Targets standard Linux AMD64 architecture used by Proxmox VE.
- `-ldflags="-s -w"`: Strips debug information and symbol tables, reducing the binary footprint to its absolute minimum.

---

## Automated Releases & Semantic Versioning

This repository integrates **Google's Release Please** workflow to automate semantic versioning (SemVer), changelog compilation, and release asset packaging based on **Conventional Commits**.

### Conventional Commit Specification
To trigger automatic version increments and changelog entries, use the following prefix formats in your commit messages:
* **`fix: <description>`**: Patches a bug (triggers a **Patch** release bump: e.g., `v1.0.0` ➔ `v1.0.1`).
* **`feat: <description>`**: Introduces a new feature (triggers a **Minor** release bump: e.g., `v1.0.0` ➔ `v1.1.0`).
* **`feat!: <description>`** or **`refactor!: <description>`**: Introduces breaking changes (triggers a **Major** release bump: e.g., `v1.0.0` ➔ `v2.0.0`).
* **`chore: <description>`** or **`docs: <description>`**: Housekeeping or documentation updates (does not trigger a release).

### The Automated Release Cycle
1. **Push Commits:** Push your Conventional Commits to the `main` branch.
2. **Release PR Generation:** The workflow scans the commit logs, calculates the next version, updates `CHANGELOG.md`, and opens a Release Pull Request (e.g., `chore(main): release v1.0.0`).
3. **Merging Release:** Merging the Release PR automatically tags the repository (e.g., `v1.0.0`) and compiles and attaches the statically linked production binary (`proxmox-api`) as a release asset.

### Troubleshooting: Workflow Permission Error
If your GitHub Actions run fails with the error:
`Error: release-please failed: GitHub Actions is not permitted to create or approve pull requests.`

You must grant GitHub Actions permission to write pull requests in your repository settings:
1. Navigate to your repository page on GitHub.
2. Click the **Settings** tab at the top.
3. In the left-hand sidebar, under **Code and automation**, click **Actions** ➔ **General**.
4. Scroll to the bottom to the **Workflow permissions** section.
5. Check the box for **"Allow GitHub Actions to create and approve pull requests"**.
6. Click **Save**.



