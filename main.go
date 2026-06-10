package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Global Configuration Variables
var (
	apiKey   string
	bindIP   string
	bindPort string
)

// JSON Response Schemas
type HostStats struct {
	CPUUtilizationPercent float64 `json:"cpu_utilization_percent"`
	RAMTotalBytes         int64   `json:"ram_total_bytes"`
	RAMUsedBytes          int64   `json:"ram_used_bytes"`
	RAMUsedPercent        float64 `json:"ram_used_percent"`
	DiskTotalBytes        int64   `json:"disk_total_bytes"`
	DiskUsedBytes         int64   `json:"disk_used_bytes"`
	DiskUsedPercent       float64 `json:"disk_used_percent"`
}

type ContainerBasic struct {
	VMID   int    `json:"vmid"`
	Status string `json:"status"`
	Name   string `json:"name"`
}

type TelemetryResponse struct {
	Host       HostStats        `json:"host"`
	Containers []ContainerBasic `json:"containers"`
}

type ContainerDetail struct {
	VMID              int     `json:"vmid"`
	Name              string  `json:"name"`
	Status            string  `json:"status"`
	CPU               float64 `json:"cpu"`
	CPUs              int     `json:"cpus"`
	MemMiB            float64 `json:"mem_mib"`
	MaxMemMiB         float64 `json:"maxmem_mib"`
	MemUtilizationPct float64 `json:"mem_utilization_percent"`
	SwapMiB           float64 `json:"swap_mib"`
	MaxSwapMiB        float64 `json:"maxswap_mib"`
	UptimeSeconds     int64   `json:"uptime_seconds"`
}

// OpenAPI 3.0 specification structural JSON (Excluding notes endpoint)
const openapiJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Proxmox Telemetry & Configuration Broker API",
    "description": "A lightweight, read-only telemetry and configuration broker API built for a Proxmox VE hypervisor host. Serves metrics and metadata to the Hermes AI agent framework.",
    "version": "1.0.0"
  },
  "paths": {
    "/api/v1/telemetry": {
      "get": {
        "summary": "Retrieve aggregated host and basic container statistics",
        "description": "Returns host CPU utilization (200ms delta sample), RAM total/used, disk total/used, and basic container status list.",
        "security": [
          {
            "ApiKeyAuth": []
          }
        ],
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/TelemetryResponse"
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized"
          }
        }
      }
    },
    "/api/v1/containers": {
      "get": {
        "summary": "List all containers in the cluster with detailed stats",
        "description": "Returns a detailed JSON array of all LXC containers with live calculated memory usage (converted to MiB) and CPU values.",
        "security": [
          {
            "ApiKeyAuth": []
          }
        ],
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/ContainerDetail"
                  }
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized"
          }
        }
      }
    },
    "/api/v1/container/config": {
      "get": {
        "summary": "Get raw container configuration",
        "description": "Returns the raw text configuration file of a container by its VMID.",
        "security": [
          {
            "ApiKeyAuth": []
          }
        ],
        "parameters": [
          {
            "name": "vmid",
            "in": "query",
            "description": "The unique numerical identifier for the container",
            "required": true,
            "schema": {
              "type": "integer"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Raw configuration text",
            "content": {
              "text/plain": {
                "schema": {
                  "type": "string"
                }
              }
            }
          },
          "400": {
            "description": "Invalid VMID parameter"
          },
          "401": {
            "description": "Unauthorized"
          },
          "404": {
            "description": "Container configuration not found"
          }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key"
      }
    },
    "schemas": {
      "TelemetryResponse": {
        "type": "object",
        "properties": {
          "host": {
            "type": "object",
            "properties": {
              "cpu_utilization_percent": { "type": "number" },
              "ram_total_bytes": { "type": "integer" },
              "ram_used_bytes": { "type": "integer" },
              "ram_used_percent": { "type": "number" },
              "disk_total_bytes": { "type": "integer" },
              "disk_used_bytes": { "type": "integer" },
              "disk_used_percent": { "type": "number" }
            }
          },
          "containers": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/ContainerBasic"
            }
          }
        }
      },
      "ContainerBasic": {
        "type": "object",
        "properties": {
          "vmid": { "type": "integer" },
          "status": { "type": "string" },
          "name": { "type": "string" }
        }
      },
      "ContainerDetail": {
        "type": "object",
        "properties": {
          "vmid": { "type": "integer" },
          "name": { "type": "string" },
          "status": { "type": "string" },
          "cpu": { "type": "number" },
          "cpus": { "type": "integer" },
          "mem_mib": { "type": "number" },
          "maxmem_mib": { "type": "number" },
          "mem_utilization_percent": { "type": "number" },
          "swap_mib": { "type": "number" },
          "maxswap_mib": { "type": "number" },
          "uptime_seconds": { "type": "integer" }
        }
      }
    }
  }
}`

// Swagger UI hosting using CDN scripts
const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Proxmox Telemetry Broker API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    body {
      margin: 0;
      background-color: #1a1a1a;
    }
    /* Simple CSS invert to present a premium dark mode Swagger UI */
    .swagger-ui {
      filter: invert(88%) hue-rotate(180deg);
    }
    .swagger-ui .topbar, .swagger-ui .scheme-container {
      background-color: #f7f7f7;
    }
    .swagger-ui .info .title {
      color: #000;
    }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" charset="UTF-8"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/swagger.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`

// Helper Functions

// getPctPath resolves the absolute path of pct to avoid systemd PATH resolution restrictions
func getPctPath() string {
	if _, err := os.Stat("/usr/sbin/pct"); err == nil {
		return "/usr/sbin/pct"
	}
	return "pct"
}

// isMockMode checks if we should run in mock mode
func isMockMode() bool {
	if os.Getenv("PROXMOX_MOCK") == "true" {
		return true
	}
	if _, err := os.Stat("/usr/sbin/pct"); err == nil {
		return false
	}
	_, err := exec.LookPath("pct")
	return err != nil
}

// runCommandWithTimeout wraps exec.Command with context deadline to prevent hanging execution threads
func runCommandWithTimeout(timeout time.Duration, name string, arg ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, arg...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// loadEnv parses custom .env key pairs from the specified filepath
func loadEnv(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	envMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
				(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
				val = val[1 : len(val)-1]
			}
			envMap[key] = val
		}
	}
	return envMap, scanner.Err()
}

// parseToMiB parses standard Proxmox / Linux memory configurations (GB/MB string suffixes)
func parseToMiB(val string) float64 {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0.0
	}

	suffix := ""
	numStr := val
	for i := len(val) - 1; i >= 0; i-- {
		r := val[i]
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			suffix = string(r) + suffix
			numStr = val[:i]
		} else {
			break
		}
	}

	numStr = strings.TrimSpace(numStr)
	var num float64
	_, err := fmt.Sscanf(numStr, "%f", &num)
	if err != nil {
		return 0.0
	}

	suffix = strings.ToLower(suffix)
	switch {
	case strings.HasPrefix(suffix, "g"):
		return num * 1024.0
	case strings.HasPrefix(suffix, "m"):
		return num
	case strings.HasPrefix(suffix, "k"):
		return num / 1024.0
	case suffix == "":
		// If no suffix and number is very large (e.g. bytes), divide to MiB
		if num > 1000000.0 {
			return num / (1024.0 * 1024.0)
		}
		return num
	default:
		return num
	}
}

// readCPUStats retrieves idle and total CPU values from /proc/stat
func readCPUStats() (idle, total int64, err error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0, fmt.Errorf("invalid cpu line structure")
			}
			var totalTime int64
			var idleTime int64
			for i := 1; i < len(fields); i++ {
				val, err := strconv.ParseInt(fields[i], 10, 64)
				if err == nil {
					totalTime += val
					if i == 4 || i == 5 { // idle and iowait
						idleTime += val
					}
				}
			}
			return idleTime, totalTime, nil
		}
	}
	return 0, 0, fmt.Errorf("cpu line not found in proc stats")
}

// getHostCPUUsage calculates host CPU percentage using a 200ms delta sample
func getHostCPUUsage() (float64, error) {
	if isMockMode() {
		return 12.5, nil
	}

	idle1, total1, err := readCPUStats()
	if err != nil {
		return 0, err
	}

	time.Sleep(200 * time.Millisecond)

	idle2, total2, err := readCPUStats()
	if err != nil {
		return 0, err
	}

	idleDelta := idle2 - idle1
	totalDelta := total2 - total1
	if totalDelta <= 0 {
		return 0.0, nil
	}

	utilization := (1.0 - (float64(idleDelta) / float64(totalDelta))) * 100.0
	return utilization, nil
}

// readHostRAM parses /proc/meminfo to retrieve RAM values in bytes
func readHostRAM() (total, used int64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var memTotal, memAvailable int64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memTotal, _ = strconv.ParseInt(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memAvailable, _ = strconv.ParseInt(fields[1], 10, 64)
			}
		}
	}

	if memTotal == 0 {
		return 0, 0, fmt.Errorf("could not parse MemTotal")
	}

	// Fallback if MemAvailable is missing
	if memAvailable == 0 {
		memAvailable = memTotal / 2
	}

	// Values in meminfo are stored in kB, convert to Bytes
	total = memTotal * 1024
	used = (memTotal - memAvailable) * 1024
	return total, used, nil
}

// getHostRAM fetches memory utilization (real or mock)
func getHostRAM() (total, used int64, err error) {
	if isMockMode() {
		return 32 * 1024 * 1024 * 1024, 16 * 1024 * 1024 * 1024, nil
	}
	return readHostRAM()
}

// getHostDiskSpace fetches local root filesystem disk storage metrics
func getHostDiskSpace() (total, used int64, err error) {
	if isMockMode() {
		return 500 * 1024 * 1024 * 1024, 200 * 1024 * 1024 * 1024, nil
	}

	var stat syscall.Statfs_t
	err = syscall.Statfs("/", &stat)
	if err != nil {
		return 0, 0, err
	}

	blockSize := uint64(stat.Bsize)
	totalBytes := int64(stat.Blocks * blockSize)
	freeBytes := int64(stat.Bavail * blockSize)
	usedBytes := totalBytes - freeBytes

	return totalBytes, usedBytes, nil
}

// getContainerList lists LXC containers (basic information)
func getContainerList() ([]ContainerBasic, error) {
	if isMockMode() {
		return []ContainerBasic{
			{VMID: 100, Status: "running", Name: "web-server"},
			{VMID: 101, Status: "stopped", Name: "database-ct"},
			{VMID: 102, Status: "running", Name: "pihole"},
		}, nil
	}

	output, err := runCommandWithTimeout(3*time.Second, getPctPath(), "list")
	if err != nil {
		return nil, fmt.Errorf("failed to execute pct list: %w", err)
	}

	var list []ContainerBasic
	lines := strings.Split(output, "\n")
	if len(lines) <= 1 {
		return list, nil
	}

	// Skip header line
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vmid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		status := fields[1]
		name := fields[len(fields)-1] // handles optional locks cleanly

		list = append(list, ContainerBasic{
			VMID:   vmid,
			Status: status,
			Name:   name,
		})
	}
	return list, nil
}

// parseContainerConfig reads the key-value config mapping of an LXC configuration file
func parseContainerConfig(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	conf := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			conf[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return conf, scanner.Err()
}

// getContainerDetails fetches rich metrics for every container in the cluster in PARALLEL
func getContainerDetails() ([]ContainerDetail, error) {
	if isMockMode() {
		return []ContainerDetail{
			{
				VMID:              100,
				Name:              "web-server",
				Status:            "running",
				CPU:               0.02,
				CPUs:              2,
				MemMiB:            256.0,
				MaxMemMiB:         1024.0,
				MemUtilizationPct: 25.0,
				SwapMiB:           128.0,
				MaxSwapMiB:        512.0,
				UptimeSeconds:     86400,
			},
			{
				VMID:              101,
				Name:              "database-ct",
				Status:            "stopped",
				CPU:               0.0,
				CPUs:              4,
				MemMiB:            0.0,
				MaxMemMiB:         4096.0,
				MemUtilizationPct: 0.0,
				SwapMiB:           0.0,
				MaxSwapMiB:        2048.0,
				UptimeSeconds:     0,
			},
			{
				VMID:              102,
				Name:              "pihole",
				Status:            "running",
				CPU:               0.01,
				CPUs:              1,
				MemMiB:            128.0,
				MaxMemMiB:         512.0,
				MemUtilizationPct: 25.0,
				SwapMiB:           64.0,
				MaxSwapMiB:        512.0,
				UptimeSeconds:     172800,
			},
		}, nil
	}

	basics, err := getContainerList()
	if err != nil {
		return nil, err
	}

	details := make([]ContainerDetail, len(basics))

	type result struct {
		index  int
		detail ContainerDetail
	}

	ch := make(chan result, len(basics))

	// Spawn status queries concurrently to avoid sequential loop delay accumulation
	for i, basic := range basics {
		go func(idx int, b ContainerBasic) {
			detail := ContainerDetail{
				VMID:   b.VMID,
				Name:   b.Name,
				Status: b.Status,
			}

			if b.Status == "running" {
				output, err := runCommandWithTimeout(2*time.Second, getPctPath(), "status", strconv.Itoa(b.VMID), "--verbose")
				if err == nil {
					scanner := bufio.NewScanner(strings.NewReader(output))
					for scanner.Scan() {
						line := scanner.Text()
						parts := strings.SplitN(line, ":", 2)
						if len(parts) != 2 {
							continue
						}
						key := strings.ToLower(strings.TrimSpace(parts[0]))
						val := strings.TrimSpace(parts[1])

						switch key {
						case "cpu":
							detail.CPU, _ = strconv.ParseFloat(val, 64)
						case "cpus":
							detail.CPUs, _ = strconv.Atoi(val)
						case "mem":
							detail.MemMiB = parseToMiB(val)
						case "maxmem":
							detail.MaxMemMiB = parseToMiB(val)
						case "swap":
							detail.SwapMiB = parseToMiB(val)
						case "maxswap":
							detail.MaxSwapMiB = parseToMiB(val)
						case "uptime":
							detail.UptimeSeconds, _ = strconv.ParseInt(val, 10, 64)
						}
					}
					if detail.MaxMemMiB > 0 {
						detail.MemUtilizationPct = (detail.MemMiB / detail.MaxMemMiB) * 100.0
					}
				} else {
					log.Printf("Warning: Failed to fetch pct status for container %d: %v", b.VMID, err)
				}
			}

			// Fill static limits from config if status run failed or was skipped
			if detail.MaxMemMiB == 0 {
				confPath := fmt.Sprintf("/etc/pve/lxc/%d.conf", b.VMID)
				if conf, parseErr := parseContainerConfig(confPath); parseErr == nil {
					if coresVal, ok := conf["cores"]; ok {
						detail.CPUs, _ = strconv.Atoi(coresVal)
					}
					if memVal, ok := conf["memory"]; ok {
						detail.MaxMemMiB = parseToMiB(memVal)
					}
					if swapVal, ok := conf["swap"]; ok {
						detail.MaxSwapMiB = parseToMiB(swapVal)
					}
				}
			}

			ch <- result{index: idx, detail: detail}
		}(i, basic)
	}

	// Gather concurrent results preserving indexing order
	for i := 0; i < len(basics); i++ {
		res := <-ch
		details[res.index] = res.detail
	}

	return details, nil
}

// getContainerRawConfig fetches raw configuration text of container
func getContainerRawConfig(vmid int) (string, error) {
	if isMockMode() {
		return fmt.Sprintf(`arch: amd64
cores: 2
features: nesting=1,keyctl=1
hostname: mock-ct-%d
memory: 1024
net0: name=eth0,bridge=vmbr0,firewall=1,hwaddr=BC:24:11:AB:CD:EF,ip=dhcp,type=veth
ostype: ubuntu
rootfs: local-lvm:subvol-%d-disk-0,size=8G
swap: 512
unprivileged: 0
description: Mock%%20Container%%20Notes%%20for%%20testing.%%0ASecurity%%20Audit%%3A%%20nesting%%3D1%%2C%%20keyctl%%3D1%%2C%%20unprivileged%%3D0.`, vmid, vmid), nil
	}

	confPath := fmt.Sprintf("/etc/pve/lxc/%d.conf", vmid)
	content, err := os.ReadFile(confPath)
	if err != nil {
		return "", fmt.Errorf("failed to read container file: %w", err)
	}
	return string(content), nil
}

// Middleware

// corsMiddleware adds global CORS permissions for preflight and standard calls
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// apiKeyMiddleware enforces Token Authorization via X-API-Key header or api_key query string
func apiKeyMiddleware(configuredKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Middleware bypass for documentation endpoints
		if r.URL.Path == "/docs" || r.URL.Path == "/swagger.json" {
			next(w, r)
			return
		}

		clientKey := r.Header.Get("X-API-Key")
		if clientKey == "" {
			clientKey = r.URL.Query().Get("api_key")
		}

		if clientKey != configuredKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Unauthorized: Invalid or missing X-API-Key header"}`))
			return
		}
		next(w, r)
	}
}

// HTTP Handlers

// handleTelemetry serves host metrics and basic container status list
func handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "Method not allowed"}`))
		return
	}

	cpuUsage, err := getHostCPUUsage()
	if err != nil {
		log.Printf("Error calculating CPU usage: %v", err)
	}

	ramTotal, ramUsed, err := getHostRAM()
	if err != nil {
		log.Printf("Error retrieving RAM usage: %v", err)
	}
	var ramUsedPercent float64
	if ramTotal > 0 {
		ramUsedPercent = (float64(ramUsed) / float64(ramTotal)) * 100.0
	}

	diskTotal, diskUsed, err := getHostDiskSpace()
	if err != nil {
		log.Printf("Error retrieving disk usage: %v", err)
	}
	var diskUsedPercent float64
	if diskTotal > 0 {
		diskUsedPercent = (float64(diskUsed) / float64(diskTotal)) * 100.0
	}

	containers, err := getContainerList()
	if err != nil {
		log.Printf("Error retrieving container list: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error": "Failed to retrieve container list: %v"}`, err)))
		return
	}

	response := TelemetryResponse{
		Host: HostStats{
			CPUUtilizationPercent: cpuUsage,
			RAMTotalBytes:         ramTotal,
			RAMUsedBytes:          ramUsed,
			RAMUsedPercent:        ramUsedPercent,
			DiskTotalBytes:        diskTotal,
			DiskUsedBytes:         diskUsed,
			DiskUsedPercent:       diskUsedPercent,
		},
		Containers: containers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleContainers serves detailed metrics of all containers
func handleContainers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "Method not allowed"}`))
		return
	}

	details, err := getContainerDetails()
	if err != nil {
		log.Printf("Error fetching container details: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

// handleContainerConfig serves raw configuration contents for container
func handleContainerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error": "Method not allowed"}`))
		return
	}

	vmidStr := r.URL.Query().Get("vmid")
	if vmidStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "vmid query parameter is required"})
		return
	}

	vmid, err := strconv.Atoi(vmidStr)
	if err != nil || vmid <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "vmid must be a valid positive integer"})
		return
	}

	configText, err := getContainerRawConfig(vmid)
	if err != nil {
		log.Printf("Error fetching config for container %d: %v", vmid, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Config not found for VMID %d", vmid)})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(configText))
}

// handleDocs returns the Swagger UI html bootstrap page
func handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(swaggerUIHTML))
}

// handleSwaggerJSON streams OpenAPI 3.0 specification back directly
func handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(openapiJSON))
}

// printConfigBanner prints the configuration information to os.Stdout
func printConfigBanner(envPath, apiKey, bindIP, bindPort string) {
	banner := `
======================================================================
  PROXMOX API BROKER - CONFIGURATION STATUS
======================================================================
  Config file path: %s

  Active settings:
  ------------------------------------------------------------------
  HERMES_API_KEY = %s
  BIND_IP        = %s
  BIND_PORT      = %s
  ------------------------------------------------------------------

  SECURITY DETAILS:
  Authenticate headers for incoming Hermes Agent requests using:
  X-API-Key: %s

  Interactive API documentation sandbox is accessible at:
  http://%s:%s/docs
======================================================================
`
	docIP := bindIP
	if bindIP == "0.0.0.0" {
		docIP = "localhost"
	}
	fmt.Printf(banner, envPath, apiKey, bindIP, bindPort, apiKey, docIP, bindPort)
}

// Main Execution
func main() {
	// 1. Resolve and initialize configuration paths
	envPath := ".env"
	configInCurrentDir := false

	if _, err := os.Stat(".env"); err == nil {
		configInCurrentDir = true
	}

	if !configInCurrentDir {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Error resolving home directory: %v", err)
		}

		configDir := filepath.Join(homeDir, ".proxmox-api")
		envPath = filepath.Join(configDir, ".env")

		// Ensure config directory exists
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			if err := os.MkdirAll(configDir, 0755); err != nil {
				log.Fatalf("Error creating config directory: %v", err)
			}
		}

		// Generate default configuration if missing
		if _, err := os.Stat(envPath); os.IsNotExist(err) {
			bytes := make([]byte, 24)
			if _, err := rand.Read(bytes); err != nil {
				log.Fatalf("Error generating secure randomized bytes: %v", err)
			}
			genKey := hex.EncodeToString(bytes)

			envContent := fmt.Sprintf("HERMES_API_KEY=%s\nBIND_IP=0.0.0.0\nBIND_PORT=8000\n", genKey)
			if err := os.WriteFile(envPath, []byte(envContent), 0600); err != nil {
				log.Fatalf("Error writing configuration environment file: %v", err)
			}
		}
	}

	// 2. Load .env config
	envMap, err := loadEnv(envPath)
	if err != nil {
		log.Fatalf("Error loading environment configurations: %v", err)
	}

	apiKey = envMap["HERMES_API_KEY"]
	bindIP = envMap["BIND_IP"]
	bindPort = envMap["BIND_PORT"]

	if apiKey == "" || bindIP == "" || bindPort == "" {
		log.Fatalf("Critical configuration variables are missing inside %s", envPath)
	}

	// Load variables into runtime environment
	os.Setenv("HERMES_API_KEY", apiKey)
	os.Setenv("BIND_IP", bindIP)
	os.Setenv("BIND_PORT", bindPort)

	// Display credential configuration banner
	printConfigBanner(envPath, apiKey, bindIP, bindPort)

	// 3. Register HTTP handlers (guarded with CORS and API authentication)
	http.HandleFunc("/api/v1/telemetry", corsMiddleware(apiKeyMiddleware(apiKey, handleTelemetry)))
	http.HandleFunc("/api/v1/containers", corsMiddleware(apiKeyMiddleware(apiKey, handleContainers)))
	http.HandleFunc("/api/v1/container/config", corsMiddleware(apiKeyMiddleware(apiKey, handleContainerConfig)))
	http.HandleFunc("/docs", corsMiddleware(handleDocs))
	http.HandleFunc("/swagger.json", corsMiddleware(handleSwaggerJSON))

	bindAddr := net.JoinHostPort(bindIP, bindPort)
	fmt.Printf("[%s] Starting Proxmox API Broker... listening on http://%s\n", time.Now().Format(time.RFC3339), bindAddr)

	if isMockMode() {
		fmt.Printf("[%s] WARNING: Proxmox CLI toolkit ('/usr/sbin/pct') not detected. Operating in MOCK MODE with realistic home lab telemetry.\n", time.Now().Format(time.RFC3339))
	} else {
		fmt.Printf("[%s] Operating in hypervisor PRODUCTION mode on Proxmox VE host.\n", time.Now().Format(time.RFC3339))
	}

	server := &http.Server{
		Addr:         bindAddr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server crashed: %v", err)
	}
}
