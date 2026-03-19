// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package config handles SPK configuration management.
// Config files use TOML format with native # comment support.
// Legacy JSONC files are auto-detected and loaded for migration.
package config

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config holds the full application configuration.
type Config struct {
	// Core
	Mode            string   `toml:"mode,omitempty" json:"mode,omitempty"`               // "server" or "client" (legacy, auto-detected)
	ListenPort      int      `toml:"listen_port,omitempty" json:"listen_port"`           // UDP port (0 = dynamic); TOML can also be "dynamic"
	ListenAddresses []string `toml:"listen_addresses,omitempty" json:"listen_addresses"` // Bind addresses (server), e.g. ["0.0.0.0", "::"]
	SnifferMode     string   `toml:"sniffer_mode,omitempty" json:"sniffer_mode"`         // "udp", "afpacket", etc.

	// Security policies
	AllowCustomPort         bool     `toml:"allow_custom_port" json:"allow_custom_port"`                   // Clients can request arbitrary ports
	AllowCustomOpenDuration bool     `toml:"allow_custom_open_duration" json:"allow_custom_open_duration"` // Clients can set their own open duration
	AllowOpenAll            bool     `toml:"allow_open_all" json:"allow_open_all"`                         // Allow "open-all" command
	AllowedPorts            []string `toml:"allowed_ports" json:"allowed_ports"`                           // Whitelisted ports, e.g. ["t22","t443","u53"]

	// Open duration (seconds)
	DefaultOpenDuration int `toml:"default_open_duration" json:"default_open_duration"` // Default port open duration
	MaxOpenDuration     int `toml:"max_open_duration" json:"max_open_duration"`         // Maximum allowed open duration
	TimestampTolerance  int `toml:"timestamp_tolerance" json:"timestamp_tolerance"`     // Knock timestamp window (anti-replay)
	NonceExpiry         int `toml:"nonce_expiry" json:"nonce_expiry"`                   // How long to remember nonces

	// Export
	ExportEncrypted bool   `toml:"export_encrypted" json:"export_encrypted"` // Encrypt activation.b64 exports
	ExportPassword  string `toml:"-" json:"-"`                               // Password for encrypted exports (never persisted to disk)

	// Firewall command templates - use {{IP}}, {{PORT}}, {{PROTO}} placeholders
	OpenTCPCommand  string `toml:"open_tcp_command" json:"open_tcp_command"`
	CloseTCPCommand string `toml:"close_tcp_command" json:"close_tcp_command"`
	OpenUDPCommand  string `toml:"open_udp_command" json:"open_udp_command"`
	CloseUDPCommand string `toml:"close_udp_command" json:"close_udp_command"`
	OpenAllCommand  string `toml:"open_all_command" json:"open_all_command"`
	CloseAllCommand string `toml:"close_all_command" json:"close_all_command"`

	// IPv6 firewall command templates - used when client IP is IPv6
	// On Linux, typically use ip6tables instead of iptables.
	OpenTCP6Command  string `toml:"open_tcp6_command" json:"open_tcp6_command"`
	CloseTCP6Command string `toml:"close_tcp6_command" json:"close_tcp6_command"`
	OpenUDP6Command  string `toml:"open_udp6_command" json:"open_udp6_command"`
	CloseUDP6Command string `toml:"close_udp6_command" json:"close_udp6_command"`
	OpenAll6Command  string `toml:"open_all6_command" json:"open_all6_command"`
	CloseAll6Command string `toml:"close_all6_command" json:"close_all6_command"`

	// Custom commands: id -> shell command. Client sends 'cust-<id>' to trigger.
	CustomCommands map[string]string `toml:"custom_commands" json:"custom_commands"`

	// Dynamic port
	DynamicPort   bool   `toml:"-" json:"dynamic_port,omitempty"`                                    // Computed: true when listen_port = "dynamic" or legacy dynamic_port = true
	PortSeed      string `toml:"port_seed,omitempty" json:"port_seed,omitempty"`                     // Hex-encoded 8-byte seed for dynamic port
	DynPortWindow int    `toml:"dynamic_port_window,omitempty" json:"dynamic_port_window,omitempty"` // Port rotation period in seconds (default: 600)
	DynPortMin    int    `toml:"dynamic_port_min,omitempty" json:"dynamic_port_min,omitempty"`       // Min port for dynamic rotation (default: 10000)
	DynPortMax    int    `toml:"dynamic_port_max,omitempty" json:"dynamic_port_max,omitempty"`       // Max port for dynamic rotation (default: 65000)

	// Security
	MatchIncomingIP bool `toml:"match_incoming_ip,omitempty" json:"match_incoming_ip,omitempty"` // Verify UDP source IP matches payload IP (disable for NAT)
	MaxNonceCache   int  `toml:"max_nonce_cache,omitempty" json:"max_nonce_cache,omitempty"`     // Max nonces to cache (default: 10000)

	// Client-specific
	ServerHost     string   `toml:"server_host,omitempty" json:"server_host,omitempty"`
	ServerPort     int      `toml:"server_port,omitempty" json:"server_port,omitempty"`
	KeyStorageMode string   `toml:"key_storage_mode,omitempty" json:"key_storage_mode,omitempty"` // "file","keychain","credential_manager"
	StunServers    []string `toml:"stun_servers,omitempty" json:"stun_servers,omitempty"`         // STUN servers for WAN IP detection. Empty or omitted disables STUN (uses local interface IP instead).

	// ML-KEM key size (768 or 1024). Default: 768 (fits within 1500 MTU).
	// 1024 provides higher security margin but packets exceed MTU and require IP fragmentation.
	KEMSize int `toml:"kem_size,omitempty" json:"kem_size,omitempty"`

	// TOTP two-factor authentication (server only)
	TOTPEnabled bool   `toml:"totp_enabled" json:"totp_enabled"`                   // Require TOTP code with each knock
	TOTPSecret  string `toml:"totp_secret,omitempty" json:"totp_secret,omitempty"` // Base32-encoded 32-char TOTP secret

	// Padding (client only)
	PaddingEnabled  bool `toml:"padding_enabled,omitempty" json:"padding_enabled,omitempty"`     // Add random padding to packets (default: false)
	PaddingMinBytes int  `toml:"padding_min_bytes,omitempty" json:"padding_min_bytes,omitempty"` // Minimum padding bytes (default: 64)
	PaddingMaxBytes int  `toml:"padding_max_bytes,omitempty" json:"padding_max_bytes,omitempty"` // Maximum padding bytes (default: 512)

	// Command execution
	CommandTimeout float64 `toml:"cmd_timeout,omitempty" json:"cmd_timeout,omitempty"` // Max seconds for each firewall/custom command (default: 0.5)

	// Logging
	LogMaxSizeMB     int  `toml:"log_max_size_mb,omitempty" json:"log_max_size_mb,omitempty"`       // Max log file size before rotation (default: 10)
	LogMaxBackups    int  `toml:"log_max_backups,omitempty" json:"log_max_backups,omitempty"`       // Max rotated log files to keep (default: 5)
	LogMaxAgeDays    int  `toml:"log_max_age_days,omitempty" json:"log_max_age_days,omitempty"`     // Max age of rotated logs in days (default: 30)
	LogFloodLimit    int  `toml:"log_flood_limit_ps,omitempty" json:"log_flood_limit_ps,omitempty"` // Max log lines per second (0 = unlimited, default: 100)
	LogCommandOutput bool `toml:"log_command_output,omitempty" json:"log_command_output,omitempty"` // Log each command before execution and its stdout/stderr output (default: false)

	// Crash recovery
	ClosePortsOnCrash bool `toml:"close_ports_on_crash" json:"close_ports_on_crash"` // Close all opened ports on crash recovery (default: true)
}

// RandomPort returns a random port in the range [10000, 65000).
func RandomPort() int {
	return 10000 + rand.IntN(55000)
}

// DefaultServerConfig returns a server config with sensible defaults.
func DefaultServerConfig() *Config {
	return &Config{
		Mode:                    "server",
		ListenPort:              RandomPort(),
		ListenAddresses:         []string{"0.0.0.0", "::"},
		SnifferMode:             "udp",
		AllowCustomPort:         false,
		AllowCustomOpenDuration: false,
		AllowOpenAll:            false,
		AllowedPorts:            []string{"t22"},
		DefaultOpenDuration:     3600,
		MaxOpenDuration:         86400,
		TimestampTolerance:      30,
		NonceExpiry:             120,
		CustomCommands:          map[string]string{},
		DynPortWindow:           600,
		DynPortMin:              10000,
		DynPortMax:              65000,
		MatchIncomingIP:         true,
		MaxNonceCache:           10000,
		ClosePortsOnCrash:       true,
		CommandTimeout:          0.5,
		KEMSize:                 768,
	}
}

// DefaultStunServers are the STUN servers used for WAN IP detection by default.
var DefaultStunServers = []string{
	"stun.cloudflare.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
}

// DefaultClientConfig returns a client config with sensible defaults.
func DefaultClientConfig() *Config {
	return &Config{
		Mode:           "client",
		KeyStorageMode: "file",
		CustomCommands: map[string]string{},
		StunServers:    DefaultStunServers,
		KEMSize:        768,
	}
}

// customConfigDir is set via --cfgdir to override the platform default.
var customConfigDir string

// configDirFallback is set when /etc/spk is not writable and the
// exe-relative config/ directory is used instead.
var configDirFallback bool

// SetConfigDir overrides the default config directory.
// Creates the directory if it does not exist.
func SetConfigDir(dir string) {
	os.MkdirAll(dir, 0750)
	customConfigDir = dir
}

// UsingFallbackConfigDir returns true when ConfigDir fell back to an
// exe-relative config/ directory because /etc/spk was not writable.
func UsingFallbackConfigDir() bool {
	return configDirFallback
}

// ConfigDir returns the platform-appropriate server config directory.
// If SetConfigDir was called, returns that override.
// Linux/macOS: /etc/spk (falls back to <exe_dir>/config if no permission)
// Windows: <exe_dir>/config
func ConfigDir() string {
	if customConfigDir != "" {
		return customConfigDir
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		dir := "/etc/spk"
		if err := os.MkdirAll(dir, 0750); err == nil {
			return dir
		}
		configDirFallback = true
		// Fall through to exe-relative config/ (same pattern as Windows)
	}
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Join(filepath.Dir(exe), "config")
	os.MkdirAll(dir, 0750) //nolint:errcheck
	return dir
}

// ClientConfigDir returns the platform-appropriate client config directory.
// Does not require root/admin privileges.
// If SetConfigDir was called, returns that override.
// Linux/macOS: $XDG_CONFIG_HOME/spk  (default: ~/.config/spk)
// Windows:     <exe_dir>\config
func ClientConfigDir() string {
	if customConfigDir != "" {
		return customConfigDir
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				base = filepath.Join(home, ".config")
			}
		}
		if base != "" {
			dir := filepath.Join(base, "spk")
			if err := os.MkdirAll(dir, 0750); err == nil {
				return dir
			}
		}
		// Fall through to exe-relative config/ as last resort
	}
	// Windows and fallback: same exe-relative layout as server.
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Join(filepath.Dir(exe), "config")
	os.MkdirAll(dir, 0750) //nolint:errcheck
	return dir
}

// ServerConfigPath returns the path to spk_server.toml.
func ServerConfigPath() string {
	return filepath.Join(ConfigDir(), "spk_server.toml")
}

// ClientConfigPath returns the path to spk_client.toml.
func ClientConfigPath() string {
	return filepath.Join(ClientConfigDir(), "spk_client.toml")
}

// DetectConfigPath auto-detects which config file exists and returns
// the path and detected mode ("server", "client", or "" if neither).
func DetectConfigPath() (string, string) {
	serverPath := ServerConfigPath()
	clientPath := ClientConfigPath()

	serverExists := fileExists(serverPath)
	clientExists := fileExists(clientPath)

	if serverExists && clientExists {
		return "", ""
	}
	if serverExists {
		return serverPath, "server"
	}
	if clientExists {
		return clientPath, "client"
	}
	return "", ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MaxPaddingBytes is the maximum allowed padding size.
// Capped to prevent excessive memory use and packet size overflow.
const MaxPaddingBytes = 2048

// MaxPaddingMTUSafe768 is the max padding that keeps ML-KEM-768 packets within 1500 MTU.
// With compact binary encoding, padding bytes are stored raw (1:1 wire overhead).
// MTU(1500) - IP(20) - UDP(8) = 1472 max UDP payload.
// Base KEM-768 packet (no padding): ~1148 bytes. Available: ~324 bytes, conservative limit -> 96 bytes.
const MaxPaddingMTUSafe768 = 96

// Validate checks config values for sanity and returns any issues.
func (c *Config) Validate() []string {
	var errs []string

	if c.ListenPort < 0 || c.ListenPort > 65535 {
		errs = append(errs, fmt.Sprintf("listen_port out of range: %d", c.ListenPort))
	}

	// Server port validation (client config)
	if c.ServerPort < 0 || c.ServerPort > 65535 {
		errs = append(errs, fmt.Sprintf("server_port out of range: %d", c.ServerPort))
	}

	// Dynamic port parameter validation
	if c.DynPortMin > 0 && c.DynPortMax > 0 && c.DynPortMin >= c.DynPortMax {
		errs = append(errs, fmt.Sprintf("dynamic_port_min (%d) must be less than dynamic_port_max (%d)", c.DynPortMin, c.DynPortMax))
	}
	if c.DynPortWindow < 0 {
		errs = append(errs, "dynamic_port_window must be >= 0")
	}
	if c.PortSeed != "" {
		// Validate hex format
		for _, ch := range c.PortSeed {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				errs = append(errs, fmt.Sprintf("port_seed must be hex-encoded, got invalid char: %c", ch))
				break
			}
		}
		if len(c.PortSeed) < 16 {
			errs = append(errs, fmt.Sprintf("port_seed too short (%d chars), need at least 16 hex chars (8 bytes)", len(c.PortSeed)))
		}
	}

	// Padding validation
	if c.PaddingEnabled {
		if c.PaddingMinBytes < 0 {
			errs = append(errs, "padding_min_bytes must be >= 0")
		}
		if c.PaddingMaxBytes > MaxPaddingBytes {
			errs = append(errs, fmt.Sprintf("padding_max_bytes exceeds maximum %d", MaxPaddingBytes))
		}
		if c.PaddingMinBytes > c.PaddingMaxBytes && c.PaddingMaxBytes > 0 {
			errs = append(errs, "padding_min_bytes must be <= padding_max_bytes")
		}
	}

	// Open duration validation
	if c.DefaultOpenDuration < 0 {
		errs = append(errs, "default_open_duration must be >= 0")
	}
	if c.MaxOpenDuration < 0 {
		errs = append(errs, "max_open_duration must be >= 0")
	}
	if c.DefaultOpenDuration > 0 && c.MaxOpenDuration > 0 && c.DefaultOpenDuration > c.MaxOpenDuration {
		errs = append(errs, fmt.Sprintf("default_open_duration (%d) exceeds max_open_duration (%d)", c.DefaultOpenDuration, c.MaxOpenDuration))
	}

	// Timestamp tolerance
	if c.TimestampTolerance < 0 {
		errs = append(errs, "timestamp_tolerance must be >= 0")
	}

	// Sniffer mode validation
	if c.SnifferMode != "" {
		validSniffers := map[string]bool{"udp": true, "afpacket": true, "pcap": true, "windivert": true}
		if !validSniffers[c.SnifferMode] {
			errs = append(errs, fmt.Sprintf("unknown sniffer_mode: %q (valid: udp, afpacket, pcap, windivert)", c.SnifferMode))
		}
	}

	// Listen addresses validation
	for _, addr := range c.ListenAddresses {
		if net.ParseIP(addr) == nil {
			errs = append(errs, fmt.Sprintf("invalid listen address: %q", addr))
		}
	}

	// TOTP secret validation
	if c.TOTPEnabled && c.TOTPSecret != "" {
		validBase32 := true
		for _, ch := range c.TOTPSecret {
			if !((ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7') || ch == '=') {
				validBase32 = false
				break
			}
		}
		if !validBase32 {
			errs = append(errs, "totp_secret must be a valid base32 string")
		}
		if len(c.TOTPSecret) < 16 {
			errs = append(errs, fmt.Sprintf("totp_secret too short (%d chars), need at least 16", len(c.TOTPSecret)))
		}
	}

	return errs
}

// StatePath returns the path to the state recovery file.
func StatePath() string {
	return filepath.Join(ConfigDir(), "state.json")
}

// Load reads a TOML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config

	// Pre-parse raw TOML to detect listen_port = "dynamic" (string value)
	// before unmarshalling into the struct (where ListenPort is int).
	var raw map[string]interface{}
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse TOML config: %w", err)
	}
	isDynamic := false
	if lp, ok := raw["listen_port"]; ok {
		if lpStr, ok := lp.(string); ok && lpStr == "dynamic" {
			isDynamic = true
			// Replace "dynamic" with 0 so struct unmarshal succeeds
			raw["listen_port"] = int64(0)
		}
	}
	// Handle server_port = "dynamic" for client config (same semantics as listen_port)
	isClientDynamic := false
	if sp, ok := raw["server_port"]; ok {
		if spStr, ok := sp.(string); ok && spStr == "dynamic" {
			isClientDynamic = true
			raw["server_port"] = int64(0)
		}
	}
	// Check legacy dynamic_port = true
	if dp, ok := raw["dynamic_port"]; ok {
		if dpBool, ok := dp.(bool); ok && dpBool {
			isDynamic = true
			isClientDynamic = true
		}
		delete(raw, "dynamic_port") // remove before re-marshal to avoid struct mismatch
	}
	// Migrate legacy listen_address (string) to listen_addresses (array)
	if la, ok := raw["listen_address"]; ok {
		if laStr, ok := la.(string); ok {
			raw["listen_addresses"] = []interface{}{laStr}
			delete(raw, "listen_address")
		}
	}
	// Re-marshal the cleaned raw map back to TOML, then unmarshal into struct
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(raw); err != nil {
		return nil, fmt.Errorf("re-encode TOML: %w", err)
	}
	if err := toml.Unmarshal(buf.Bytes(), &cfg); err != nil {
		return nil, fmt.Errorf("parse TOML config: %w", err)
	}
	if isDynamic {
		cfg.DynamicPort = true
		cfg.ListenPort = 0
	}
	if isClientDynamic {
		cfg.DynamicPort = true
		cfg.ServerPort = 0
	}

	// Client-side: if server_port is a real port number (>=1), disable dynamic
	// regardless of port_seed or dynamic_port_window presence.
	if cfg.ServerPort >= 1 && cfg.ServerPort <= 65535 && cfg.ServerHost != "" {
		cfg.DynamicPort = false
	}

	// Server-side: if listen_port is a real port number (>=1), static mode wins.
	// Dynamic port is only used when listen_port = "dynamic" (0) and port_seed exists.
	if cfg.ServerHost == "" { // server config
		if cfg.ListenPort >= 1 && cfg.ListenPort <= 65535 {
			cfg.DynamicPort = false
		} else if cfg.PortSeed != "" && !cfg.DynamicPort {
			cfg.DynamicPort = true
		}
	}
	return &cfg, nil
}

// Save writes the config as TOML.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	var buf bytes.Buffer
	encoder := toml.NewEncoder(&buf)
	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// WriteServerConfigWithComments generates the initial server config with documentation.
func WriteServerConfigWithComments(path string, cfg *Config) error {
	platform := runtime.GOOS
	var content strings.Builder

	content.WriteString("# SPK Server Configuration\n")
	content.WriteString("# ==================================\n")
	content.WriteString("# Edit this file to configure firewall commands and policies.\n")
	content.WriteString("# Lines starting with # are comments.\n")
	content.WriteString("\n")
	content.WriteString("# ========== NETWORK ==========\n")
	if cfg.DynamicPort {
		content.WriteString("# \"dynamic\" = port rotates based on shared seed (stealth).\n")
		content.WriteString("# Set to a number (e.g. 45678) to use a fixed port instead.\n")
		content.WriteString("listen_port = \"dynamic\"\n")
	} else {
		content.WriteString("# Set to \"dynamic\" for automatic port rotation, or a fixed port number.\n")
		content.WriteString(fmt.Sprintf("listen_port = %d\n", cfg.ListenPort))
	}
	// Listen addresses: array of IPs to bind on. Default: ["0.0.0.0", "::"] for both IPv4 and IPv6.
	content.WriteString("# Bind addresses. Use [\"0.0.0.0\", \"::\"] for all IPv4 + IPv6 interfaces.\n")
	content.WriteString("# [\"0.0.0.0\"] = IPv4 only, [\"::\"] = IPv6 only, or specific IPs.\n")
	addrs := cfg.ListenAddresses
	if len(addrs) == 0 {
		addrs = []string{"0.0.0.0", "::"}
	}
	content.WriteString(fmt.Sprintf("listen_addresses = %s\n", tomlStringArray(addrs)))
	content.WriteString("# Packet capture backend. Possible values:\n")
	content.WriteString("#   \"udp\"       - Universal UDP socket listener. No dependencies.\n")
	content.WriteString("#                  Port visible in scans (not stealth). Works everywhere.\n")
	content.WriteString("#                  NOTE: With dynamic_port enabled, the UDP listener binds\n")
	content.WriteString("#                  to the current port. When the port rotates, the new port\n")
	content.WriteString("#                  may already be in use by another process, causing a\n")
	content.WriteString("#                  startup failure. Use a stealth sniffer mode (afpacket,\n")
	content.WriteString("#                  pcap, windivert) to avoid this limitation.\n")
	content.WriteString("#   \"afpacket\"  - AF_PACKET raw socket (Linux only). Stealth mode.\n")
	content.WriteString("#                  Pure Go, no dependencies. Requires root or CAP_NET_RAW.\n")
	content.WriteString("#   \"pcap\"      - libpcap / Npcap. Stealth mode, cross-platform.\n")
	content.WriteString("#                  Requires libpcap (Linux/macOS) or Npcap (Windows)\n")
	content.WriteString("#                  and must be compiled with -tags pcap.\n")
	content.WriteString("#   \"windivert\" - WinDivert kernel driver (Windows only). Stealth mode.\n")
	content.WriteString("#                  Requires WinDivert.dll + WinDivert64.sys.\n")
	content.WriteString("#                  Download: https://reqrypt.org/windivert.html\n")
	content.WriteString(fmt.Sprintf("sniffer_mode = \"%s\"\n", cfg.SnifferMode))

	content.WriteString("\n# ========== SECURITY POLICIES ==========\n")
	content.WriteString("# allow_custom_port: if true, clients can request any port (e.g. open-t8080).\n")
	content.WriteString("#   If false, only ports listed in allowed_ports are accepted.\n")
	content.WriteString(fmt.Sprintf("allow_custom_port = %v\n", cfg.AllowCustomPort))
	content.WriteString("# allow_custom_open_duration: if true, clients can set their own port-open duration.\n")
	content.WriteString("#   If false, all ports use default_open_duration.\n")
	content.WriteString(fmt.Sprintf("allow_custom_open_duration = %v\n", cfg.AllowCustomOpenDuration))
	content.WriteString("# allow_open_all: if true, clients can send 'open-all' to open every allowed port.\n")
	content.WriteString("#   When allow_custom_port is also true, 'open-all' opens ALL system ports (tcp+udp).\n")
	content.WriteString(fmt.Sprintf("allow_open_all = %v\n", cfg.AllowOpenAll))
	content.WriteString("# allowed_ports: whitelist of ports clients can open. Prefix t=TCP, u=UDP.\n")
	content.WriteString("# NOTE: This list is ignored when allow_custom_port = true (any port is allowed).\n")
	content.WriteString(fmt.Sprintf("allowed_ports = %s\n", tomlStringArray(cfg.AllowedPorts)))

	content.WriteString("\n# ========== OPEN DURATION (seconds) ==========\n")
	content.WriteString("# default_open_duration: how long a port stays open before being automatically closed.\n")
	content.WriteString("#   Used when the client does not specify a custom duration (or custom duration is disabled).\n")
	content.WriteString(fmt.Sprintf("default_open_duration = %d\n", cfg.DefaultOpenDuration))
	content.WriteString("# max_open_duration: upper limit for port-open duration. Clients cannot exceed this even\n")
	content.WriteString("#   with allow_custom_open_duration = true.\n")
	content.WriteString(fmt.Sprintf("max_open_duration = %d\n", cfg.MaxOpenDuration))
	content.WriteString("# timestamp_tolerance: how many seconds of clock drift to allow between client and\n")
	content.WriteString("#   server. Knock packets with a timestamp outside +/- this window are rejected.\n")
	content.WriteString("#   Increase if client/server clocks are not synchronized (e.g. no NTP).\n")
	content.WriteString(fmt.Sprintf("timestamp_tolerance = %d\n", cfg.TimestampTolerance))
	content.WriteString("# nonce_expiry: how long (seconds) the server remembers used nonces to prevent\n")
	content.WriteString("#   replay attacks. Must be >= timestamp_tolerance. Increase for slower networks.\n")
	content.WriteString(fmt.Sprintf("nonce_expiry = %d\n", cfg.NonceExpiry))

	// Export settings (export_encrypted, export_password) are NOT persisted to config.
	// Passwords should never be stored in plaintext config files.
	// Use --export to create encrypted bundles with an interactive password prompt.
	content.WriteString("\n# ========== EXPORT ==========\n")
	content.WriteString("# Passwords should never be stored in plaintext config files.\n")
	content.WriteString("# Use --export to create encrypted activation bundles with an\n")
	content.WriteString("# interactive password prompt. The password is never saved.\n")

	content.WriteString("\n# ========== FIREWALL COMMAND TEMPLATES ==========\n")
	content.WriteString("# Use {{IP}} for client IP, {{PORT}} for port number.\n")
	content.WriteString("# Set these to match YOUR firewall. Leave empty to skip.\n")

	if platform == "linux" {
		content.WriteString("#\n")
		content.WriteString("# --- iptables examples ---\n")
		content.WriteString("# open_tcp_command  = \"iptables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# close_tcp_command = \"iptables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# open_udp_command  = \"iptables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# close_udp_command = \"iptables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("#\n")
		content.WriteString("# --- ufw examples ---\n")
		content.WriteString("# open_tcp_command  = \"ufw allow from {{IP}} to any port {{PORT}} proto tcp\"\n")
		content.WriteString("# close_tcp_command = \"ufw delete allow from {{IP}} to any port {{PORT}} proto tcp\"\n")
		content.WriteString("#\n")
		content.WriteString("# --- nftables examples ---\n")
		content.WriteString("# open_tcp_command  = \"nft add rule inet filter input ip saddr {{IP}} tcp dport {{PORT}} accept\"\n")
		content.WriteString("# close_tcp_command = \"nft delete rule inet filter input handle $(nft -a list chain inet filter input | grep '{{IP}}.*{{PORT}}' | awk '{print $NF}')\"\n")
	} else if platform == "windows" {
		content.WriteString("#\n")
		content.WriteString("# --- Windows Firewall (netsh) examples ---\n")
		content.WriteString("# open_tcp_command  = \"netsh advfirewall firewall add rule name=\\\"SPK_{{IP}}_{{PORT}}\\\" dir=in action=allow protocol=tcp localport={{PORT}} remoteip={{IP}}\"\n")
		content.WriteString("# close_tcp_command = \"netsh advfirewall firewall delete rule name=\\\"SPK_{{IP}}_{{PORT}}\\\"\"\n")
		content.WriteString("# open_udp_command  = \"netsh advfirewall firewall add rule name=\\\"SPK_{{IP}}_{{PORT}}_U\\\" dir=in action=allow protocol=udp localport={{PORT}} remoteip={{IP}}\"\n")
		content.WriteString("# close_udp_command = \"netsh advfirewall firewall delete rule name=\\\"SPK_{{IP}}_{{PORT}}_U\\\"\"\n")
	} else if platform == "darwin" {
		content.WriteString("#\n")
		content.WriteString("# --- macOS pf examples ---\n")
		content.WriteString("# open_tcp_command  = \"echo \\\"pass in proto tcp from {{IP}} to any port {{PORT}}\\\" | pfctl -a spk -f -\"\n")
		content.WriteString("# close_tcp_command = \"pfctl -a spk -F rules\"\n")
	}

	content.WriteString(fmt.Sprintf("\nopen_tcp_command = \"%s\"\n", escapeToml(cfg.OpenTCPCommand)))
	content.WriteString(fmt.Sprintf("close_tcp_command = \"%s\"\n", escapeToml(cfg.CloseTCPCommand)))
	content.WriteString(fmt.Sprintf("open_udp_command = \"%s\"\n", escapeToml(cfg.OpenUDPCommand)))
	content.WriteString(fmt.Sprintf("close_udp_command = \"%s\"\n", escapeToml(cfg.CloseUDPCommand)))
	content.WriteString(fmt.Sprintf("open_all_command = \"%s\"\n", escapeToml(cfg.OpenAllCommand)))
	content.WriteString(fmt.Sprintf("close_all_command = \"%s\"\n", escapeToml(cfg.CloseAllCommand)))

	content.WriteString("\n# ========== IPv6 FIREWALL COMMANDS ==========\n")
	content.WriteString("# Used when client IP is IPv6. Leave empty to skip IPv6.\n")
	if platform == "linux" {
		content.WriteString("# On Linux, use ip6tables for IPv6 (separate from iptables for IPv4):\n")
		content.WriteString("# open_tcp6_command  = \"ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# close_tcp6_command = \"ip6tables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# open_udp6_command  = \"ip6tables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# close_udp6_command = \"ip6tables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# open_all6_command  = \"ip6tables -A INPUT -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("# close_all6_command = \"ip6tables -D INPUT -s {{IP}} -j ACCEPT\"\n")
		content.WriteString("#\n")
		content.WriteString("# nftables 'inet' family handles both IPv4 and IPv6:\n")
		content.WriteString("# nft add rule inet filter input ip6 saddr {{IP}} tcp dport {{PORT}} accept\n")
	} else if platform == "windows" {
		content.WriteString("# Windows netsh handles both IPv4 and IPv6 natively - use the same templates.\n")
	} else if platform == "darwin" {
		content.WriteString("# macOS pf handles both IPv4 and IPv6 natively - use the same templates.\n")
	}
	content.WriteString(fmt.Sprintf("open_tcp6_command = \"%s\"\n", escapeToml(cfg.OpenTCP6Command)))
	content.WriteString(fmt.Sprintf("close_tcp6_command = \"%s\"\n", escapeToml(cfg.CloseTCP6Command)))
	content.WriteString(fmt.Sprintf("open_udp6_command = \"%s\"\n", escapeToml(cfg.OpenUDP6Command)))
	content.WriteString(fmt.Sprintf("close_udp6_command = \"%s\"\n", escapeToml(cfg.CloseUDP6Command)))
	content.WriteString(fmt.Sprintf("open_all6_command = \"%s\"\n", escapeToml(cfg.OpenAll6Command)))
	content.WriteString(fmt.Sprintf("close_all6_command = \"%s\"\n", escapeToml(cfg.CloseAll6Command)))

	content.WriteString("\n# ========== DYNAMIC PORT SETTINGS ==========\n")
	content.WriteString("# When listen_port = \"dynamic\", the port rotates based on a shared seed.\n")
	content.WriteString("# Both server and client must have the same seed to compute the same port.\n")
	content.WriteString("# The seed is shared via the activation bundle (QR code / b64 file).\n")
	if cfg.PortSeed != "" {
		content.WriteString(fmt.Sprintf("port_seed = \"%s\"\n", cfg.PortSeed))
	} else {
		content.WriteString("# port_seed = \"<generated during setup>\"\n")
	}
	dynWindow := cfg.DynPortWindow
	if dynWindow == 0 {
		dynWindow = 600
	}
	content.WriteString(fmt.Sprintf("dynamic_port_window = %d    # Rotation period in seconds (60-86400)\n", dynWindow))
	dpMin := cfg.DynPortMin
	if dpMin == 0 {
		dpMin = 10000
	}
	dpMax := cfg.DynPortMax
	if dpMax == 0 {
		dpMax = 65000
	}
	content.WriteString(fmt.Sprintf("dynamic_port_min = %d         # Minimum port for rotation range\n", dpMin))
	content.WriteString(fmt.Sprintf("dynamic_port_max = %d         # Maximum port for rotation range\n", dpMax))

	content.WriteString("\n# ========== SECURITY ==========\n")
	content.WriteString("# match_incoming_ip: if true (default), UDP source IP must match the IP in the knock payload.\n")
	content.WriteString("# Set false if clients are behind NAT where source IP differs from payload IP.\n")
	content.WriteString("# When false, the client-specified IP in the payload is used for port opening.\n")
	content.WriteString(fmt.Sprintf("match_incoming_ip = %v\n", cfg.MatchIncomingIP))
	maxNonce := cfg.MaxNonceCache
	if maxNonce == 0 {
		maxNonce = 10000
	}
	content.WriteString("# max_nonce_cache: max nonces to track for anti-replay (limits memory).\n")
	content.WriteString(fmt.Sprintf("max_nonce_cache = %d\n", maxNonce))

	content.WriteString("\n# ========== COMMAND EXECUTION ==========\n")
	content.WriteString("# cmd_timeout: max seconds for each firewall/custom command (default: 0.5).\n")
	content.WriteString("# If a command does not finish within this time, it is killed.\n")
	content.WriteString("# Prevents hung commands (e.g. ping) from blocking the server.\n")
	content.WriteString("# Accepts sub-second values: 0.1 = 100ms, 0.5 = 500ms, 2.0 = 2s.\n")
	if cfg.CommandTimeout > 0 {
		content.WriteString(fmt.Sprintf("cmd_timeout = %.1f\n", cfg.CommandTimeout))
	} else {
		content.WriteString("cmd_timeout = 0.5\n")
	}

	content.WriteString("\n# ========== LOGGING ==========\n")
	content.WriteString("# Logs: Linux/macOS -> /var/log/spk/, Windows -> <exe_dir>/log/\n")
	content.WriteString("# Override with --logdir at the command line.\n")
	content.WriteString("log_max_size_mb = 10\n")
	content.WriteString("log_max_backups = 5\n")
	content.WriteString("log_max_age_days = 30\n")
	content.WriteString("log_flood_limit_ps = 100\n")
	content.WriteString("\n# log_command_output: log stdout/stderr of every executed command.\n")
	content.WriteString("# Useful for debugging custom commands. Can generate verbose output.\n")
	content.WriteString(fmt.Sprintf("log_command_output = %v\n", cfg.LogCommandOutput))

	content.WriteString("\n# ========== TOTP TWO-FACTOR AUTHENTICATION ==========\n")
	content.WriteString("# When enabled, clients must include a valid 6-digit TOTP code with each knock.\n")
	content.WriteString("# The TOTP secret is shared out-of-band (QR code / manual entry in authenticator app).\n")
	content.WriteString("# Uses RFC 6238 (HMAC-SHA1, 30-second period, +/- step tolerance).\n")
	content.WriteString(fmt.Sprintf("totp_enabled = %v\n", cfg.TOTPEnabled))
	if cfg.TOTPSecret != "" {
		content.WriteString(fmt.Sprintf("totp_secret = \"%s\"\n", cfg.TOTPSecret))
	} else {
		content.WriteString("# totp_secret = \"<generated during setup>\"\n")
	}

	// [custom_commands] MUST be the last section in the TOML file.
	// TOML tables consume all subsequent key=value pairs until the next table header,
	// so placing a table in the middle would swallow everything below it.
	content.WriteString("\n# ========== CUSTOM COMMANDS ==========\n")
	content.WriteString("# Define ID->command pairs. Client sends 'cust-<id>', server runs the command.\n")
	content.WriteString("# Example: client sends 'cust-1' to run command \"1\", 'cust-ping' for \"ping\".\n")
	content.WriteString("# IMPORTANT: This section MUST remain at the bottom of the config file.\n")
	content.WriteString("#\n")
	content.WriteString("# [custom_commands]\n")
	content.WriteString("# 1 = \"systemctl restart sshd\"\n")
	content.WriteString("# 2 = \"apt update && apt upgrade -y\"\n")
	content.WriteString("# ping = \"ping -c 4 google.com\"\n")
	if len(cfg.CustomCommands) > 0 {
		content.WriteString("\n[custom_commands]\n")
		for k, v := range cfg.CustomCommands {
			content.WriteString(fmt.Sprintf("%s = \"%s\"\n", k, escapeToml(v)))
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return os.WriteFile(path, []byte(content.String()), 0600)
}

func escapeToml(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

func tomlStringArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	parts := make([]string, len(arr))
	for i, s := range arr {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// WriteClientConfigWithComments generates the initial client config with documentation.
func WriteClientConfigWithComments(path string, cfg *Config) error {
	var content strings.Builder

	content.WriteString("# SPK Client Configuration\n")
	content.WriteString("# ==================================\n")
	content.WriteString("# Settings for connecting to the SPK server.\n")
	content.WriteString("# Most settings are auto-populated from the server's activation bundle.\n")
	content.WriteString("\n")
	content.WriteString("# ========== SERVER CONNECTION ==========\n")
	content.WriteString(fmt.Sprintf("server_host = \"%s\"\n", escapeToml(cfg.ServerHost)))
	if cfg.DynamicPort {
		content.WriteString("# \"dynamic\" = port rotates based on shared seed.\n")
		content.WriteString("# Set to a number (e.g. 45678) to use a fixed port and disable rotation.\n")
		content.WriteString("server_port = \"dynamic\"\n")
	} else if cfg.ServerPort > 0 {
		content.WriteString("# Set to \"dynamic\" for automatic port rotation, or a fixed port number.\n")
		content.WriteString("# Using a fixed port disables dynamic rotation even if port_seed is set.\n")
		content.WriteString(fmt.Sprintf("server_port = %d\n", cfg.ServerPort))
	}

	content.WriteString("\n# ========== DYNAMIC PORT ==========\n")
	content.WriteString("# These values come from the server's activation bundle.\n")
	content.WriteString("# Do NOT change unless re-importing a new bundle.\n")
	if cfg.PortSeed != "" {
		content.WriteString(fmt.Sprintf("port_seed = \"%s\"\n", cfg.PortSeed))
	}
	if cfg.DynPortWindow > 0 {
		content.WriteString(fmt.Sprintf("dynamic_port_window = %d\n", cfg.DynPortWindow))
	}
	if cfg.DynPortMin > 0 {
		content.WriteString(fmt.Sprintf("dynamic_port_min = %d\n", cfg.DynPortMin))
	}
	if cfg.DynPortMax > 0 {
		content.WriteString(fmt.Sprintf("dynamic_port_max = %d\n", cfg.DynPortMax))
	}

	content.WriteString("\n# ========== CLIENT SETTINGS ==========\n")
	content.WriteString("# key_storage: where to store the server's public key.\n")
	content.WriteString("#   \"file\"               - plaintext file (server.crt)\n")
	content.WriteString("#   \"credential_manager\"  - OS secure storage (Windows/macOS/Linux)\n")
	content.WriteString(fmt.Sprintf("key_storage_mode = \"%s\"\n", cfg.KeyStorageMode))

	content.WriteString("\n# ========== PADDING ==========\n")
	content.WriteString("# Add random padding to knock packets to vary packet sizes.\n")
	content.WriteString("# When enabled, each packet gets a random amount of padding, making packet\n")
	content.WriteString("# sizes variable and harder to fingerprint. The server ignores padding content.\n")
	content.WriteString(fmt.Sprintf("# Maximum allowed: %d bytes.\n", MaxPaddingBytes))
	content.WriteString(fmt.Sprintf("padding_enabled = %v\n", cfg.PaddingEnabled))
	if cfg.PaddingMinBytes > 0 {
		content.WriteString(fmt.Sprintf("padding_min_bytes = %d\n", cfg.PaddingMinBytes))
	} else {
		content.WriteString("# padding_min_bytes = 2      # Minimum padding bytes\n")
	}
	if cfg.PaddingMaxBytes > 0 {
		content.WriteString(fmt.Sprintf("padding_max_bytes = %d\n", cfg.PaddingMaxBytes))
	} else {
		content.WriteString("# padding_max_bytes = 96     # Maximum padding bytes\n")
	}

	content.WriteString("\n# ========== STUN SERVERS ==========\n")
	content.WriteString("# Used for WAN IP auto-detection when --ip is not specified.\n")
	content.WriteString("# The client tries each server in order and uses the first successful response.\n")
	content.WriteString("# Override to use your preferred STUN servers.\n")
	content.WriteString("#\n")
	content.WriteString("# Leave empty or comment out to DISABLE STUN. When disabled, the client uses\n")
	content.WriteString("# the local interface IP selected by the OS routing table instead of the public\n")
	content.WriteString("# WAN IP. This is correct for LAN/VPN setups where the server can see your\n")
	content.WriteString("# local IP directly, but will likely fail if you are behind NAT on the internet.\n")
	content.WriteString("# When STUN is disabled a warning is printed at connect time.\n")
	content.WriteString("#\n")
	content.WriteString("# Public STUN servers:\n")
	content.WriteString("#   stun.cloudflare.com:3478        (Cloudflare - default, fast)\n")
	content.WriteString("#   stun.l.google.com:19302         (Google)\n")
	content.WriteString("#   stun1.l.google.com:19302        (Google secondary)\n")
	content.WriteString("#   stun.stunprotocol.org:3478      (Open STUN)\n")
	content.WriteString("#   stun.nextcloud.com:443          (Nextcloud)\n")
	content.WriteString("#   stun.sipnet.net:3478            (SIPnet)\n")
	if len(cfg.StunServers) > 0 {
		content.WriteString(fmt.Sprintf("stun_servers = %s\n", tomlStringArray(cfg.StunServers)))
	} else {
		content.WriteString(fmt.Sprintf("stun_servers = %s\n", tomlStringArray(DefaultStunServers)))
	}

	content.WriteString("\n# ========== SERVER POLICIES (from bundle, read-only) ==========\n")
	content.WriteString("# These reflect what the server allows. Changing them has no effect.\n")
	content.WriteString(fmt.Sprintf("allow_custom_open_duration = %v\n", cfg.AllowCustomOpenDuration))
	content.WriteString(fmt.Sprintf("allow_custom_port = %v\n", cfg.AllowCustomPort))
	content.WriteString(fmt.Sprintf("allow_open_all = %v\n", cfg.AllowOpenAll))
	if cfg.DefaultOpenDuration > 0 {
		content.WriteString(fmt.Sprintf("default_open_duration = %d\n", cfg.DefaultOpenDuration))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return os.WriteFile(path, []byte(content.String()), 0600)
}

// WaitForUserOrTimeout waits up to timeoutSec seconds for user to press Enter.
// Used after setup wizards to keep the window open so users can read output.
func WaitForUserOrTimeout(timeoutSec int) {
	fmt.Printf("\nWindow will close in %d seconds. Press Enter to continue...\n", timeoutSec)

	done := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		done <- struct{}{}
	}()

	timer := time.NewTimer(time.Duration(timeoutSec) * time.Second)
	defer timer.Stop()

	select {
	case <-done:
		return
	case <-timer.C:
		return
	}
}
