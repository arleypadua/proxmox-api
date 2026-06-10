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
	CPUUtilizationPercent float64         `json:"cpu_utilization_percent"`
	RAMTotalBytes         int64           `json:"ram_total_bytes"`
	RAMUsedBytes          int64           `json:"ram_used_bytes"`
	RAMUsedPercent        float64         `json:"ram_used_percent"`
	DiskTotalBytes        int64           `json:"disk_total_bytes"`
	DiskUsedBytes         int64           `json:"disk_used_bytes"`
	DiskUsedPercent       float64         `json:"disk_used_percent"`
	StorageStatus         *StorageStatus  `json:"storage_status,omitempty"`
}

type StorageStatus struct {
	PVESMStatus string          `json:"pvesm_status,omitempty"`
	ZPoolStatus string          `json:"zpool_status,omitempty"`
	Devices     json.RawMessage `json:"devices,omitempty"` // Raw JSON output from lsblk -J
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

type NetworkInterface struct {
	Name   string `json:"name"`
	Bridge string `json:"bridge"`
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	GW     string `json:"gw"`
	IP6    string `json:"ip6"`
	GW6    string `json:"gw6"`
}

// Deep Probe Schemas
type DNSProbe struct {
	Type       string   `json:"type"` // "adguard" or "pihole"
	Upstreams  []string `json:"upstreams"`
	Bootstraps []string `json:"bootstraps,omitempty"`
}

type ReverseProxyProbe struct {
	Count       int      `json:"count"`
	ProxyPasses []string `json:"proxy_passes"`
}

type VPNProbe struct {
	TunActive bool   `json:"tun_active"`
	Connected bool   `json:"connected"`
	IPReport  string `json:"ip_report,omitempty"`
}

type DockerContainer struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Ports  string `json:"ports"`
}

type DockerProbe struct {
	Installed  bool              `json:"installed"`
	Containers []DockerContainer `json:"containers,omitempty"`
}

type ContainerProbes struct {
	DNS          *DNSProbe          `json:"dns,omitempty"`
	ReverseProxy *ReverseProxyProbe `json:"reverse_proxy,omitempty"`
	VPN          *VPNProbe          `json:"vpn,omitempty"`
	Docker       *DockerProbe       `json:"docker,omitempty"`
}

type ContainerDetail struct {
	VMID              int                `json:"vmid"`
	Name              string             `json:"name"`
	Status            string             `json:"status"`
	CPU               float64            `json:"cpu"`
	CPUs              int                `json:"cpus"`
	MemMiB            float64            `json:"mem_mib"`
	MaxMemMiB         float64            `json:"maxmem_mib"`
	MemUtilizationPct float64            `json:"mem_utilization_percent"`
	SwapMiB           float64            `json:"swap_mib"`
	MaxSwapMiB        float64            `json:"maxswap_mib"`
	UptimeSeconds     int64              `json:"uptime_seconds"`
	NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
	LiveIPAddresses   []string           `json:"live_ip_addresses"`
	OpenPorts         []int              `json:"open_ports"`
	Probes            *ContainerProbes   `json:"probes,omitempty"`
}

// OpenAPI 3.0 specification structural JSON (Updated with deep probes)
const openapiJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Proxmox Telemetry & Configuration Broker API",
    "description": "A lightweight, read-only telemetry and configuration broker API built for a Proxmox VE hypervisor host. Serves metrics, deep configuration probes, and container details to the Hermes AI agent framework.",
    "version": "1.0.0"
  },
  "paths": {
    "/api/v1/telemetry": {
      "get": {
        "summary": "Retrieve aggregated host and basic container statistics",
        "description": "Returns host CPU utilization (200ms delta sample), RAM total/used, disk total/used, host storage details (PVESM, ZFS, mounts), and basic container status list.",
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
        "description": "Returns a detailed JSON array of all LXC containers with live calculated memory usage, CPU values, network configurations, active IPs, open ports, and deep service probes (Docker, DNS, Reverse Proxy, VPN).",
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
              "disk_used_percent": { "type": "number" },
              "storage_status": {
                "$ref": "#/components/schemas/StorageStatus"
              }
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
      "StorageStatus": {
        "type": "object",
        "properties": {
          "pvesm_status": { "type": "string" },
          "zpool_status": { "type": "string" },
          "devices": { "type": "object", "description": "Raw lsblk JSON structure" }
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
      "NetworkInterface": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "bridge": { "type": "string" },
          "mac": { "type": "string" },
          "ip": { "type": "string" },
          "gw": { "type": "string" },
          "ip6": { "type": "string" },
          "gw6": { "type": "string" }
        }
      },
      "DNSProbe": {
        "type": "object",
        "properties": {
          "type": { "type": "string" },
          "upstreams": { "type": "array", "items": { "type": "string" } },
          "bootstraps": { "type": "array", "items": { "type": "string" } }
        }
      },
      "ReverseProxyProbe": {
        "type": "object",
        "properties": {
          "count": { "type": "integer" },
          "proxy_passes": { "type": "array", "items": { "type": "string" } }
        }
      },
      "VPNProbe": {
        "type": "object",
        "properties": {
          "tun_active": { "type": "boolean" },
          "connected": { "type": "boolean" },
          "ip_report": { "type": "string" }
        }
      },
      "DockerContainer": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "status": { "type": "string" },
          "ports": { "type": "string" }
        }
      },
      "DockerProbe": {
        "type": "object",
        "properties": {
          "installed": { "type": "boolean" },
          "containers": { "type": "array", "items": { "$ref": "#/components/schemas/DockerContainer" } }
        }
      },
      "ContainerProbes": {
        "type": "object",
        "properties": {
          "dns": { "$ref": "#/components/schemas/DNSProbe" },
          "reverse_proxy": { "$ref": "#/components/schemas/ReverseProxyProbe" },
          "vpn": { "$ref": "#/components/schemas/VPNProbe" },
          "docker": { "$ref": "#/components/schemas/DockerProbe" }
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
          "uptime_seconds": { "type": "integer" },
          "network_interfaces": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/NetworkInterface"
            }
          },
          "live_ip_addresses": {
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          "open_ports": {
            "type": "array",
            "items": {
              "type": "integer"
            }
          },
          "probes": {
            "$ref": "#/components/schemas/ContainerProbes"
          }
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

// getHostStorageStatus retrieves ZFS status, PVESM storage limits, and block devices
func getHostStorageStatus() (*StorageStatus, error) {
	if isMockMode() {
		mockDevices := []byte(`{"blockdevices": [{"name": "sda", "size": "1.8T", "fstype": "zfs_member"}]}`)
		return &StorageStatus{
			PVESMStatus: "Name             Type     Status           Total            Used       Available        %\\nlocal             dir     active       982334812        42318991     839213812    4.31%\\nlocal-lvm      lvmthin     active       239012390        12930219     226082171    5.41%",
			ZPoolStatus: "  pool: tank\\n state: ONLINE\\n  scan: scrub repaired 0B in 01:23:45 with 0 errors on Sun Jun  7 02:23:45 2026\\nconfig:\\n\\n\\tNAME        STATE     READ WRITE CKSUM\\n\\ttank        ONLINE       0     0     0\\n\\t  mirror-0  ONLINE       0     0     0\\n\\t    sda     ONLINE       0     0     0\\n\\t    sdb     ONLINE       0     0     0\\n\\nerrors: No known data errors",
			Devices:     json.RawMessage(mockDevices),
		}, nil
	}

	status := &StorageStatus{}

	// 1. pvesm status check
	if pveOut, err := runCommandWithTimeout(3*time.Second, "pvesm", "status"); err == nil {
		status.PVESMStatus = pveOut
	}

	// 2. zpool status check
	if zfsOut, err := runCommandWithTimeout(3*time.Second, "zpool", "status"); err == nil {
		status.ZPoolStatus = zfsOut
	}

	// 3. lsblk JSON details
	if lsblkOut, err := runCommandWithTimeout(3*time.Second, "lsblk", "-o", "NAME,SIZE,FSTYPE,MOUNTPOINT,LABEL", "-J"); err == nil {
		status.Devices = json.RawMessage(lsblkOut)
	}

	return status, nil
}

// getContainerList lists LXC containers (basic information)
func getContainerList() ([]ContainerBasic, error) {
	if isMockMode() {
		return []ContainerBasic{
			{VMID: 100, Status: "running", Name: "npm-router"},
			{VMID: 101, Status: "stopped", Name: "database-ct"},
			{VMID: 102, Status: "running", Name: "pihole-dns"},
			{VMID: 104, Status: "running", Name: "torrent-vpn"},
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

// parseNetValue parses raw config net0, net1 settings into structured data
func parseNetValue(val string) NetworkInterface {
	netConf := NetworkInterface{}
	parts := strings.Split(val, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			switch k {
			case "name":
				netConf.Name = v
			case "bridge":
				netConf.Bridge = v
			case "hwaddr":
				netConf.MAC = v
			case "ip":
				netConf.IP = v
			case "gw":
				netConf.GW = v
			case "ip6":
				netConf.IP6 = v
			case "gw6":
				netConf.GW6 = v
			}
		}
	}
	return netConf
}

// getContainerNetworkConfig reads the static network configuration of LXC from conf files
func getContainerNetworkConfig(vmid int) ([]NetworkInterface, error) {
	if isMockMode() {
		return []NetworkInterface{
			{
				Name:   "eth0",
				Bridge: "vmbr0",
				MAC:    "BC:24:11:AB:CD:EF",
				IP:     "dhcp",
				GW:     "192.168.2.1",
			},
		}, nil
	}

	confPath := fmt.Sprintf("/etc/pve/lxc/%d.conf", vmid)
	conf, err := parseContainerConfig(confPath)
	if err != nil {
		return nil, err
	}

	var interfaces []NetworkInterface
	for k, v := range conf {
		if strings.HasPrefix(k, "net") {
			netConf := parseNetValue(v)
			interfaces = append(interfaces, netConf)
		}
	}
	return interfaces, nil
}

// getContainerLiveIPs fetches actual live IP addresses via hostname -I inside the container
func getContainerLiveIPs(vmid int) ([]string, error) {
	if isMockMode() {
		if vmid == 100 {
			return []string{"192.168.2.150"}, nil
		}
		if vmid == 101 {
			return []string{"192.168.2.151"}, nil
		}
		if vmid == 102 {
			return []string{"192.168.2.152", "fe80::bc24:11ff:feab:cdef"}, nil
		}
		return []string{"192.168.2.200"}, nil
	}

	output, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "hostname", "-I")
	if err != nil {
		return nil, err
	}

	var ips []string
	fields := strings.Fields(output)
	for _, field := range fields {
		ips = append(ips, strings.TrimSpace(field))
	}
	return ips, nil
}

// getContainerOpenPorts fetches listening TCP ports inside container (ss -> netstat)
func getContainerOpenPorts(vmid int) ([]int, error) {
	if isMockMode() {
		if vmid == 100 {
			return []int{80, 443}, nil
		}
		if vmid == 101 {
			return []int{3306}, nil
		}
		if vmid == 102 {
			return []int{53, 80}, nil
		}
		return []int{22}, nil
	}

	output, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "ss", "-tln")
	if err != nil {
		// Fallback to netstat if ss is missing
		output, err = runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "netstat", "-tln")
		if err != nil {
			return nil, err
		}
	}

	var ports []int
	seen := make(map[int]bool)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addrPort := fields[4]
		idx := strings.LastIndex(addrPort, ":")
		if idx != -1 && idx < len(addrPort)-1 {
			portStr := addrPort[idx+1:]
			if p, err := strconv.Atoi(portStr); err == nil {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		}
	}
	return ports, nil
}

// deepProbeContainer performs specific DNS, Reverse Proxy, VPN, and Docker probes inside the running container
func deepProbeContainer(vmid int, name string) *ContainerProbes {
	probes := &ContainerProbes{}
	loweredName := strings.ToLower(name)

	// 1. DNS / Ad-Blocker Probing
	if strings.Contains(loweredName, "dns") || strings.Contains(loweredName, "adguard") || strings.Contains(loweredName, "pihole") {
		dns := &DNSProbe{}
		// Check for AdGuard Home config
		if isMockMode() {
			dns.Type = "adguard"
			dns.Upstreams = []string{"https://dns.cloudflare.com/dns-query", "1.1.1.1"}
			dns.Bootstraps = []string{"9.9.9.9"}
			probes.DNS = dns
		} else {
			if adgYaml, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "cat", "/opt/AdGuardHome/AdGuardHome.yaml"); err == nil {
				dns.Type = "adguard"
				scanner := bufio.NewScanner(strings.NewReader(adgYaml))
				inUpstreams := false
				inBootstraps := false
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if strings.HasPrefix(line, "upstream_dns:") {
						inUpstreams = true
						inBootstraps = false
						continue
					}
					if strings.HasPrefix(line, "bootstrap_dns:") {
						inBootstraps = true
						inUpstreams = false
						continue
					}
					// If we hit another root block, stop collecting
					if len(line) > 0 && !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, " ") && !strings.Contains(line, "_dns:") {
						inUpstreams = false
						inBootstraps = false
					}
					if strings.HasPrefix(line, "- ") {
						val := strings.TrimPrefix(line, "- ")
						val = strings.Trim(val, "\"' ")
						if inUpstreams {
							dns.Upstreams = append(dns.Upstreams, val)
						} else if inBootstraps {
							dns.Bootstraps = append(dns.Bootstraps, val)
						}
					}
				}
				probes.DNS = dns
			} else if piVars, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "cat", "/etc/pihole/setupVars.conf"); err == nil {
				dns.Type = "pihole"
				scanner := bufio.NewScanner(strings.NewReader(piVars))
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if strings.HasPrefix(line, "PIHOLE_DNS_") {
						parts := strings.SplitN(line, "=", 2)
						if len(parts) == 2 {
							dns.Upstreams = append(dns.Upstreams, strings.TrimSpace(parts[1]))
						}
					}
				}
				probes.DNS = dns
			}
		}
	}

	// 2. Reverse Proxy Probing (Nginx Proxy Manager / Traefik / Nginx)
	if strings.Contains(loweredName, "npm") || strings.Contains(loweredName, "nginx") || strings.Contains(loweredName, "proxy") {
		proxy := &ReverseProxyProbe{}
		if isMockMode() {
			proxy.Count = 3
			proxy.ProxyPasses = []string{"http://192.168.2.200:8080", "https://192.168.2.152:443", "http://192.168.2.100:3000"}
			probes.ReverseProxy = proxy
		} else {
			// Find configurations count in NPM directory
			if listOut, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "find", "/data/nginx/proxy_host", "-name", "*.conf"); err == nil {
				scanner := bufio.NewScanner(strings.NewReader(listOut))
				count := 0
				for scanner.Scan() {
					if strings.TrimSpace(scanner.Text()) != "" {
						count++
					}
				}
				proxy.Count = count

				// Grep proxy_pass configurations to map target endpoints
				if passesOut, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "sh", "-c", "grep -h 'proxy_pass' /data/nginx/proxy_host/*.conf 2>/dev/null"); err == nil {
					scannerPasses := bufio.NewScanner(strings.NewReader(passesOut))
					seen := make(map[string]bool)
					for scannerPasses.Scan() {
						fields := strings.Fields(scannerPasses.Text())
						if len(fields) >= 2 {
							target := strings.TrimSuffix(fields[1], ";")
							if !seen[target] {
								seen[target] = true
								proxy.ProxyPasses = append(proxy.ProxyPasses, target)
							}
						}
					}
				}
				probes.ReverseProxy = proxy
			}
		}
	}

	// 3. VPN / Torrent Probing (Checks for VPN leaks and connections)
	if strings.Contains(loweredName, "qbittorrent") || strings.Contains(loweredName, "vpn") || strings.Contains(loweredName, "torrent") {
		vpn := &VPNProbe{}
		if isMockMode() {
			vpn.TunActive = true
			vpn.Connected = true
			vpn.IPReport = "Mullvad VPN Connected (IP: 185.213.154.12)"
			probes.VPN = vpn
		} else {
			// Check if tun0 interface exists
			if _, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "ip", "addr", "show", "tun0"); err == nil {
				vpn.TunActive = true
				// Check external IP Mullvad VPN connectivity status
				if checkOut, err := runCommandWithTimeout(3*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "curl", "-s", "--max-time", "2", "https://am.i.mullvad.net/connected"); err == nil {
					vpn.Connected = strings.Contains(strings.ToLower(checkOut), "connected")
					vpn.IPReport = strings.TrimSpace(checkOut)
				}
			} else {
				vpn.TunActive = false
				vpn.Connected = false
			}
			probes.VPN = vpn
		}
	}

	// 4. Docker Overlay Probing
	docker := &DockerProbe{}
	if isMockMode() {
		if vmid == 100 || vmid == 104 {
			docker.Installed = true
			docker.Containers = []DockerContainer{
				{Name: "coolify-helper", Status: "Up 2 hours", Ports: "80/tcp"},
				{Name: "app-backend", Status: "Up 3 days", Ports: "8080->8080/tcp"},
			}
			probes.Docker = docker
		}
	} else {
		if _, err := runCommandWithTimeout(2*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "command", "-v", "docker"); err == nil {
			docker.Installed = true
			// Query Docker containers details in pseudo CSV
			if docOut, err := runCommandWithTimeout(3*time.Second, getPctPath(), "exec", strconv.Itoa(vmid), "--", "docker", "ps", "--format", "{{.Names}}||{{.Status}}||{{.Ports}}"); err == nil {
				scanner := bufio.NewScanner(strings.NewReader(docOut))
				for scanner.Scan() {
					line := scanner.Text()
					parts := strings.Split(line, "||")
					if len(parts) >= 2 {
						container := DockerContainer{
							Name:   strings.TrimSpace(parts[0]),
							Status: strings.TrimSpace(parts[1]),
						}
						if len(parts) >= 3 {
							container.Ports = strings.TrimSpace(parts[2])
						}
						docker.Containers = append(docker.Containers, container)
					}
				}
			}
			probes.Docker = docker
		}
	}

	// Return probes only if at least one service probe was activated
	if probes.DNS != nil || probes.ReverseProxy != nil || probes.VPN != nil || probes.Docker != nil {
		return probes
	}
	return nil
}

// getContainerDetails fetches rich metrics for every container in the cluster in PARALLEL
func getContainerDetails() ([]ContainerDetail, error) {
	if isMockMode() {
		return []ContainerDetail{
			{
				VMID:              100,
				Name:              "npm-router",
				Status:            "running",
				CPU:               0.02,
				CPUs:              2,
				MemMiB:            256.0,
				MaxMemMiB:         1024.0,
				MemUtilizationPct: 25.0,
				SwapMiB:           128.0,
				MaxSwapMiB:        512.0,
				UptimeSeconds:     86400,
				NetworkInterfaces: []NetworkInterface{
					{Name: "eth0", Bridge: "vmbr0", MAC: "BC:24:11:AB:CD:EF", IP: "dhcp", GW: "192.168.2.1"},
				},
				LiveIPAddresses: []string{"192.168.2.150"},
				OpenPorts:       []int{80, 443},
				Probes: &ContainerProbes{
					ReverseProxy: &ReverseProxyProbe{
						Count: 3,
						ProxyPasses: []string{"http://192.168.2.200:8080", "https://192.168.2.152:443", "http://192.168.2.100:3000"},
					},
					Docker: &DockerProbe{
						Installed: true,
						Containers: []DockerContainer{
							{Name: "coolify-helper", Status: "Up 2 hours", Ports: "80/tcp"},
						},
					},
				},
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
				NetworkInterfaces: []NetworkInterface{
					{Name: "eth0", Bridge: "vmbr0", MAC: "BC:24:11:11:22:33", IP: "192.168.2.101/24", GW: "192.168.2.1"},
				},
				LiveIPAddresses: nil,
				OpenPorts:       nil,
				Probes:          nil,
			},
			{
				VMID:              102,
				Name:              "pihole-dns",
				Status:            "running",
				CPU:               0.01,
				CPUs:              1,
				MemMiB:            128.0,
				MaxMemMiB:         512.0,
				MemUtilizationPct: 25.0,
				SwapMiB:           64.0,
				MaxSwapMiB:        512.0,
				UptimeSeconds:     172800,
				NetworkInterfaces: []NetworkInterface{
					{Name: "eth0", Bridge: "vmbr0", MAC: "BC:24:11:44:55:66", IP: "dhcp", GW: "192.168.2.1"},
				},
				LiveIPAddresses: []string{"192.168.2.152", "fe80::bc24:11ff:feab:cdef"},
				OpenPorts:       []int{53, 80},
				Probes: &ContainerProbes{
					DNS: &DNSProbe{
						Type:      "pihole",
						Upstreams: []string{"1.1.1.1", "8.8.8.8"},
					},
				},
			},
			{
				VMID:              104,
				Name:              "torrent-vpn",
				Status:            "running",
				CPU:               0.05,
				CPUs:              2,
				MemMiB:            512.0,
				MaxMemMiB:         2048.0,
				MemUtilizationPct: 25.0,
				SwapMiB:           256.0,
				MaxSwapMiB:        1024.0,
				UptimeSeconds:     43200,
				NetworkInterfaces: []NetworkInterface{
					{Name: "eth0", Bridge: "vmbr0", MAC: "BC:24:11:77:88:99", IP: "dhcp", GW: "192.168.2.1"},
				},
				LiveIPAddresses: []string{"192.168.2.154"},
				OpenPorts:       []int{8112, 6881},
				Probes: &ContainerProbes{
					VPN: &VPNProbe{
						TunActive: true,
						Connected: true,
						IPReport:  "Mullvad VPN Connected (IP: 185.213.154.12)",
					},
				},
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
				VMID:              b.VMID,
				Name:              b.Name,
				Status:            b.Status,
				NetworkInterfaces: make([]NetworkInterface, 0),
				LiveIPAddresses:   make([]string, 0),
				OpenPorts:         make([]int, 0),
			}

			// 1. Fetch static interface config (always available from /etc/pve/lxc/*.conf)
			if netConfigs, err := getContainerNetworkConfig(b.VMID); err == nil {
				detail.NetworkInterfaces = netConfigs
			}

			if b.Status == "running" {
				// 2. Fetch verbose stats
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

				// 3. Fetch runtime live IP addresses
				if ips, err := getContainerLiveIPs(b.VMID); err == nil {
					detail.LiveIPAddresses = ips
				} else {
					log.Printf("Warning: Failed to query live IPs for container %d: %v", b.VMID, err)
				}

				// 4. Fetch open TCP listening ports
				if ports, err := getContainerOpenPorts(b.VMID); err == nil {
					detail.OpenPorts = ports
				} else {
					log.Printf("Warning: Failed to query open ports for container %d: %v", b.VMID, err)
				}

				// 5. Deep Probing Services (DNS, NPM, VPN, Docker)
				detail.Probes = deepProbeContainer(b.VMID, b.Name)
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

	// Fetch Host Storage deep details
	storageStatus, err := getHostStorageStatus()
	if err != nil {
		log.Printf("Error retrieving host storage: %v", err)
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
			StorageStatus:         storageStatus,
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
		ReadTimeout:  15 * time.Second, // Increased timeout to support extensive storage + network deep probes
		WriteTimeout: 15 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server crashed: %v", err)
	}
}
