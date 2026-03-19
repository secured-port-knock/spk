// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.Mode != "server" {
		t.Errorf("mode = %s, want server", cfg.Mode)
	}
	if cfg.ListenPort < 10000 || cfg.ListenPort >= 65000 {
		t.Errorf("listen port %d out of expected range [10000, 65000)", cfg.ListenPort)
	}
	if cfg.DefaultOpenDuration != 3600 {
		t.Errorf("default open duration = %d, want 3600", cfg.DefaultOpenDuration)
	}
	if cfg.TimestampTolerance != 30 {
		t.Errorf("timestamp tolerance = %d, want 30", cfg.TimestampTolerance)
	}
	if !cfg.MatchIncomingIP {
		t.Error("MatchIncomingIP should default to true")
	}
	if !cfg.ClosePortsOnCrash {
		t.Error("ClosePortsOnCrash should default to true")
	}
	if len(cfg.ListenAddresses) != 2 || cfg.ListenAddresses[0] != "0.0.0.0" || cfg.ListenAddresses[1] != "::" {
		t.Errorf("ListenAddresses = %v, want [0.0.0.0, ::]", cfg.ListenAddresses)
	}
	if cfg.MaxNonceCache != 10000 {
		t.Errorf("MaxNonceCache = %d, want 10000", cfg.MaxNonceCache)
	}
}

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()

	if cfg.Mode != "client" {
		t.Errorf("mode = %s, want client", cfg.Mode)
	}
	if cfg.KeyStorageMode != "" && cfg.KeyStorageMode != "file" {
		t.Errorf("key storage = %s, want file", cfg.KeyStorageMode)
	}
}

func TestSaveLoadConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 44444
	cfg.AllowCustomPort = true
	cfg.AllowedPorts = []string{"t22", "t443", "u53"}
	cfg.CustomCommands = map[string]string{
		"restart_ssh": "systemctl restart sshd",
	}

	path := filepath.Join(t.TempDir(), "test_config.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.ListenPort != 44444 {
		t.Errorf("listen port = %d, want 44444", loaded.ListenPort)
	}
	if !loaded.AllowCustomPort {
		t.Error("allow custom port = false, want true")
	}
	if len(loaded.AllowedPorts) != 3 {
		t.Errorf("allowed ports length = %d, want 3", len(loaded.AllowedPorts))
	}
	if loaded.CustomCommands["restart_ssh"] != "systemctl restart sshd" {
		t.Error("custom command not preserved")
	}
}

func TestWriteServerConfigWithComments(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 33333

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	// Verify file contains TOML comments
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "# SPK Server Configuration") {
		t.Error("TOML config should contain # comments")
	}
	// Verify file does not contain // as a standalone (non-TOML) comment style.
	// URLs inside # comments (e.g. https://...) are acceptable.
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // skip TOML comment lines (may contain URLs with //)
		}
		if strings.Contains(trimmed, "//") {
			t.Errorf("TOML config contains // outside a comment: %s", trimmed)
		}
	}

	// Should be readable as TOML
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load commented config: %v", err)
	}

	if loaded.ListenPort != 33333 {
		t.Errorf("port = %d, want 33333", loaded.ListenPort)
	}
	// mode is no longer written to config (auto-detected from filename)
	if !loaded.MatchIncomingIP {
		t.Error("MatchIncomingIP should default to true")
	}
}

func TestRandomPort(t *testing.T) {
	// Test that random ports are in expected range
	for i := 0; i < 100; i++ {
		p := RandomPort()
		if p < 10000 || p >= 65000 {
			t.Errorf("RandomPort() = %d, out of range [10000, 65000)", p)
		}
	}
}

func TestConfigPaths(t *testing.T) {
	serverPath := ServerConfigPath()
	clientPath := ClientConfigPath()

	if serverPath == "" {
		t.Error("ServerConfigPath should not be empty")
	}
	if clientPath == "" {
		t.Error("ClientConfigPath should not be empty")
	}

	// Should have correct filenames
	if filepath.Base(serverPath) != "spk_server.toml" {
		t.Errorf("server config filename = %s, want spk_server.toml", filepath.Base(serverPath))
	}
	if filepath.Base(clientPath) != "spk_client.toml" {
		t.Errorf("client config filename = %s, want spk_client.toml", filepath.Base(clientPath))
	}
}

func TestStatePath(t *testing.T) {
	sp := StatePath()
	if sp == "" {
		t.Error("StatePath should not be empty")
	}
	if filepath.Base(sp) != "state.json" {
		t.Errorf("state path filename = %s, want state.json", filepath.Base(sp))
	}
}

func TestConfigDirNotEmpty(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir should not return empty string")
	}
}

func TestDetectConfigPath(t *testing.T) {
	// When neither file exists, should return empty
	// This may detect actual config files if present,
	// so we just verify it doesn't panic
	path, mode := DetectConfigPath()
	_ = path
	_ = mode
}

func TestFileExists(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "exists.txt")
	if fileExists(tmpFile) {
		t.Error("file should not exist yet")
	}

	os.WriteFile(tmpFile, []byte("hello"), 0644)
	if !fileExists(tmpFile) {
		t.Error("file should exist now")
	}
}

func TestLoggingConfigFields(t *testing.T) {
	cfg := DefaultServerConfig()
	// Verify logging fields exist and have zero values (defaults in logging package)
	if cfg.LogMaxSizeMB != 0 {
		t.Errorf("LogMaxSizeMB = %d, want 0 (default)", cfg.LogMaxSizeMB)
	}

	// Set and save
	cfg.LogMaxSizeMB = 20
	cfg.LogMaxBackups = 10
	cfg.LogMaxAgeDays = 60
	cfg.LogFloodLimit = 200

	path := filepath.Join(t.TempDir(), "log_cfg.toml")
	cfg.Save(path)

	loaded, _ := Load(path)
	if loaded.LogMaxSizeMB != 20 {
		t.Errorf("LogMaxSizeMB = %d, want 20", loaded.LogMaxSizeMB)
	}
	if loaded.LogMaxBackups != 10 {
		t.Errorf("LogMaxBackups = %d, want 10", loaded.LogMaxBackups)
	}
	if loaded.LogMaxAgeDays != 60 {
		t.Errorf("LogMaxAgeDays = %d, want 60", loaded.LogMaxAgeDays)
	}
	if loaded.LogFloodLimit != 200 {
		t.Errorf("LogFloodLimit = %d, want 200", loaded.LogFloodLimit)
	}
}

func TestLoadTOMLConfig(t *testing.T) {
	content := `# SPK Server Config
mode = "server"
listen_port = 42000
listen_addresses = ["0.0.0.0"]
sniffer_mode = "udp"
allow_custom_port = true
allow_custom_open_duration = false
allow_open_all = true
allowed_ports = ["t22", "t443"]
default_open_duration = 7200
max_open_duration = 86400
timestamp_tolerance = 30
nonce_expiry = 120
export_encrypted = false
match_incoming_ip = false
max_nonce_cache = 50000
`

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load TOML: %v", err)
	}

	if cfg.ListenPort != 42000 {
		t.Errorf("port = %d, want 42000", cfg.ListenPort)
	}
	if !cfg.AllowCustomPort {
		t.Error("allow custom port should be true")
	}
	if !cfg.AllowOpenAll {
		t.Error("allow open all should be true")
	}
	if len(cfg.AllowedPorts) != 2 {
		t.Errorf("allowed ports = %d, want 2", len(cfg.AllowedPorts))
	}
	if cfg.MatchIncomingIP {
		t.Error("match_incoming_ip should be false in this config")
	}
	if cfg.MaxNonceCache != 50000 {
		t.Errorf("max_nonce_cache = %d, want 50000", cfg.MaxNonceCache)
	}
}

func TestTOMLCustomCommands(t *testing.T) {
	content := `mode = "server"
listen_port = 12345
listen_addresses = ["0.0.0.0"]

[custom_commands]
1 = "systemctl restart sshd"
ping = "ping -c 4 google.com"
`

	path := filepath.Join(t.TempDir(), "custom_cmd.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load TOML with custom_commands: %v", err)
	}

	if cfg.CustomCommands["1"] != "systemctl restart sshd" {
		t.Errorf("custom command 1 = %q, want %q", cfg.CustomCommands["1"], "systemctl restart sshd")
	}
	if cfg.CustomCommands["ping"] != "ping -c 4 google.com" {
		t.Errorf("custom command ping = %q, want %q", cfg.CustomCommands["ping"], "ping -c 4 google.com")
	}
}

func TestLoadTOMLDynamicPort(t *testing.T) {
	content := `listen_port = "dynamic"
listen_addresses = ["0.0.0.0"]
port_seed = "abcdef0123456789"
dynamic_port_window = 300
dynamic_port_min = 20000
dynamic_port_max = 50000
`

	path := filepath.Join(t.TempDir(), "dynamic.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load dynamic port TOML: %v", err)
	}

	if !cfg.DynamicPort {
		t.Error("DynamicPort should be true when listen_port = \"dynamic\"")
	}
	if cfg.ListenPort != 0 {
		t.Errorf("ListenPort = %d, want 0 when dynamic", cfg.ListenPort)
	}
	if cfg.PortSeed != "abcdef0123456789" {
		t.Errorf("PortSeed = %q, want %q", cfg.PortSeed, "abcdef0123456789")
	}
	if cfg.DynPortWindow != 300 {
		t.Errorf("DynPortWindow = %d, want 300", cfg.DynPortWindow)
	}
	if cfg.DynPortMin != 20000 {
		t.Errorf("DynPortMin = %d, want 20000", cfg.DynPortMin)
	}
	if cfg.DynPortMax != 50000 {
		t.Errorf("DynPortMax = %d, want 50000", cfg.DynPortMax)
	}
}

func TestWriteServerConfigDynamic(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.DynamicPort = true
	cfg.PortSeed = "1234567890abcdef"
	cfg.DynPortWindow = 120

	path := filepath.Join(t.TempDir(), "srv_dyn.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, `listen_port = "dynamic"`) {
		t.Error("config should contain listen_port = \"dynamic\"")
	}
	if strings.Contains(content, "dynamic_port = true") {
		t.Error("config should NOT contain dynamic_port = true (replaced by listen_port = \"dynamic\")")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.DynamicPort {
		t.Error("loaded DynamicPort should be true")
	}
	if loaded.PortSeed != "1234567890abcdef" {
		t.Errorf("PortSeed = %q", loaded.PortSeed)
	}
}

func TestWriteClientConfigWithComments(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerHost = "example.com"
	cfg.ServerPort = 12345
	cfg.DynamicPort = true
	cfg.PortSeed = "aabbccdd11223344"
	cfg.DynPortWindow = 300
	cfg.AllowCustomOpenDuration = true
	cfg.AllowOpenAll = true

	path := filepath.Join(t.TempDir(), "client.toml")
	if err := WriteClientConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "# SPK Client Configuration") {
		t.Error("client config should have # comments")
	}
	if !strings.Contains(content, "example.com") {
		t.Error("should contain server host")
	}
	if !strings.Contains(content, "aabbccdd11223344") {
		t.Error("should contain port seed")
	}
	if !strings.Contains(content, "read-only") {
		t.Error("should document policies as read-only")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load client config: %v", err)
	}
	if loaded.ServerHost != "example.com" {
		t.Errorf("ServerHost = %q, want example.com", loaded.ServerHost)
	}
	if !loaded.DynamicPort {
		t.Error("DynamicPort should be true (inferred from port_seed)")
	}
}

func TestDefaultServerConfigPortRange(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.DynPortMin != 10000 {
		t.Errorf("DynPortMin = %d, want 10000", cfg.DynPortMin)
	}
	if cfg.DynPortMax != 65000 {
		t.Errorf("DynPortMax = %d, want 65000", cfg.DynPortMax)
	}
}

func TestIPv6CommandFields(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.OpenTCP6Command = "ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
	cfg.CloseTCP6Command = "ip6tables -D INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"
	cfg.OpenUDP6Command = "ip6tables -A INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
	cfg.CloseUDP6Command = "ip6tables -D INPUT -p udp --dport {{PORT}} -s {{IP}} -j ACCEPT"
	cfg.OpenAll6Command = "ip6tables -A INPUT -s {{IP}} -j ACCEPT"
	cfg.CloseAll6Command = "ip6tables -D INPUT -s {{IP}} -j ACCEPT"

	path := filepath.Join(t.TempDir(), "ipv6_cfg.toml")
	cfg.Save(path)

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.OpenTCP6Command != cfg.OpenTCP6Command {
		t.Errorf("OpenTCP6Command = %q, want %q", loaded.OpenTCP6Command, cfg.OpenTCP6Command)
	}
	if loaded.CloseTCP6Command != cfg.CloseTCP6Command {
		t.Errorf("CloseTCP6Command = %q", loaded.CloseTCP6Command)
	}
	if loaded.OpenAll6Command != cfg.OpenAll6Command {
		t.Errorf("OpenAll6Command = %q", loaded.OpenAll6Command)
	}
	if loaded.CloseAll6Command != cfg.CloseAll6Command {
		t.Errorf("CloseAll6Command = %q", loaded.CloseAll6Command)
	}
}

func TestWriteServerConfigIPv6Section(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.OpenTCP6Command = "ip6tables -A INPUT -p tcp --dport {{PORT}} -s {{IP}} -j ACCEPT"

	path := filepath.Join(t.TempDir(), "srv_ipv6.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "IPv6 FIREWALL") {
		t.Error("config should contain IPv6 firewall section header")
	}
	if !strings.Contains(content, "open_tcp6_command") {
		t.Error("config should contain open_tcp6_command")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.OpenTCP6Command != cfg.OpenTCP6Command {
		t.Errorf("loaded OpenTCP6Command = %q", loaded.OpenTCP6Command)
	}
}

func TestLogCommandOutputField(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.LogCommandOutput {
		t.Error("LogCommandOutput should default to false")
	}

	cfg.LogCommandOutput = true
	path := filepath.Join(t.TempDir(), "logcmd.toml")
	cfg.Save(path)

	loaded, _ := Load(path)
	if !loaded.LogCommandOutput {
		t.Error("loaded LogCommandOutput should be true")
	}
}

func TestStunServersConfig(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.StunServers = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

	path := filepath.Join(t.TempDir(), "stun_cfg.toml")
	cfg.Save(path)

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.StunServers) != 2 {
		t.Errorf("StunServers length = %d, want 2", len(loaded.StunServers))
	}
	if len(loaded.StunServers) > 0 && loaded.StunServers[0] != "stun.cloudflare.com:3478" {
		t.Errorf("StunServers[0] = %q, want stun.cloudflare.com:3478", loaded.StunServers[0])
	}
}

func TestWriteClientConfigStunServers(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerHost = "test.example.com"
	cfg.ServerPort = 11111
	cfg.StunServers = []string{"stun.custom.com:3478"}

	path := filepath.Join(t.TempDir(), "client_stun.toml")
	if err := WriteClientConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "STUN SERVERS") {
		t.Error("client config should contain STUN SERVERS section")
	}
	if !strings.Contains(content, "stun.custom.com:3478") {
		t.Error("client config should contain custom STUN server")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.StunServers) != 1 || loaded.StunServers[0] != "stun.custom.com:3478" {
		t.Errorf("StunServers = %v, want [stun.custom.com:3478]", loaded.StunServers)
	}
}

func TestClientIPFieldRemoved(t *testing.T) {
	// Verify that ClientIP field no longer exists in config struct.
	// Config with client_ip should load without error (ignored as unknown field).
	content := `server_host = "test.com"
server_port = 12345
client_ip = "1.2.3.4"
`
	path := filepath.Join(t.TempDir(), "old_client.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Loading should succeed - TOML ignores unknown fields
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load config with old client_ip field: %v", err)
	}
	if cfg.ServerHost != "test.com" {
		t.Errorf("ServerHost = %q, want test.com", cfg.ServerHost)
	}
}

func TestClosePortsOnCrashTOMLRoundTrip(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ClosePortsOnCrash = false

	path := filepath.Join(t.TempDir(), "crash_test.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.ClosePortsOnCrash {
		t.Error("ClosePortsOnCrash should be false after round-trip")
	}
}

// =============================================================================
// ListenAddresses tests
// =============================================================================

func TestListenAddressesDefault(t *testing.T) {
	cfg := DefaultServerConfig()
	if len(cfg.ListenAddresses) != 2 {
		t.Fatalf("default ListenAddresses length = %d, want 2", len(cfg.ListenAddresses))
	}
	if cfg.ListenAddresses[0] != "0.0.0.0" {
		t.Errorf("ListenAddresses[0] = %q, want 0.0.0.0", cfg.ListenAddresses[0])
	}
	if cfg.ListenAddresses[1] != "::" {
		t.Errorf("ListenAddresses[1] = %q, want ::", cfg.ListenAddresses[1])
	}
}

func TestListenAddressesTOMLRoundTrip(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenAddresses = []string{"192.168.1.1", "::1"}
	cfg.ListenPort = 11111

	path := filepath.Join(t.TempDir(), "listen_addr.toml")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.ListenAddresses) != 2 {
		t.Fatalf("loaded ListenAddresses length = %d, want 2", len(loaded.ListenAddresses))
	}
	if loaded.ListenAddresses[0] != "192.168.1.1" {
		t.Errorf("ListenAddresses[0] = %q, want 192.168.1.1", loaded.ListenAddresses[0])
	}
	if loaded.ListenAddresses[1] != "::1" {
		t.Errorf("ListenAddresses[1] = %q, want ::1", loaded.ListenAddresses[1])
	}
}

func TestLegacyListenAddressMigration(t *testing.T) {
	// Legacy config with listen_address (string) should be migrated to listen_addresses (array)
	content := `listen_port = 33333
listen_address = "192.168.1.100"
`
	path := filepath.Join(t.TempDir(), "legacy.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load legacy config: %v", err)
	}
	if len(cfg.ListenAddresses) != 1 {
		t.Fatalf("ListenAddresses length = %d, want 1", len(cfg.ListenAddresses))
	}
	if cfg.ListenAddresses[0] != "192.168.1.100" {
		t.Errorf("ListenAddresses[0] = %q, want 192.168.1.100", cfg.ListenAddresses[0])
	}
}

func TestListenAddressesInServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 22222

	path := filepath.Join(t.TempDir(), "srv_addrs.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "listen_addresses") {
		t.Error("server config should contain listen_addresses")
	}
	if !strings.Contains(content, "0.0.0.0") {
		t.Error("server config should contain 0.0.0.0")
	}
	if !strings.Contains(content, "::") {
		t.Error("server config should contain ::")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.ListenAddresses) != 2 {
		t.Errorf("loaded ListenAddresses length = %d, want 2", len(loaded.ListenAddresses))
	}
}

// =============================================================================
// Client server_port = "dynamic" tests
// =============================================================================

func TestClientServerPortDynamic(t *testing.T) {
	content := `server_host = "example.com"
server_port = "dynamic"
port_seed = "abcdef0123456789"
dynamic_port_window = 600
`
	path := filepath.Join(t.TempDir(), "client_dyn.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DynamicPort {
		t.Error("DynamicPort should be true when server_port = \"dynamic\"")
	}
	if cfg.ServerPort != 0 {
		t.Errorf("ServerPort = %d, want 0 when dynamic", cfg.ServerPort)
	}
}

func TestClientStaticPortDisablesDynamic(t *testing.T) {
	// When server_port is a real port number, dynamic should be disabled
	// even if port_seed is present
	content := `server_host = "example.com"
server_port = 45678
port_seed = "abcdef0123456789"
dynamic_port_window = 600
`
	path := filepath.Join(t.TempDir(), "client_static.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DynamicPort {
		t.Error("DynamicPort should be false when server_port is a port number")
	}
	if cfg.ServerPort != 45678 {
		t.Errorf("ServerPort = %d, want 45678", cfg.ServerPort)
	}
}

func TestWriteClientConfigDynamic(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerHost = "test.example.com"
	cfg.DynamicPort = true
	cfg.PortSeed = "1122334455667788"
	cfg.DynPortWindow = 300

	path := filepath.Join(t.TempDir(), "client_dyn_write.toml")
	if err := WriteClientConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, `server_port = "dynamic"`) {
		t.Error("client config should contain server_port = \"dynamic\"")
	}
	if strings.Contains(content, "kem_size") {
		t.Error("client config should NOT contain kem_size")
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.DynamicPort {
		t.Error("loaded DynamicPort should be true")
	}
}

func TestWriteClientConfigStaticPort(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerHost = "test.example.com"
	cfg.ServerPort = 45678
	cfg.DynamicPort = false

	path := filepath.Join(t.TempDir(), "client_static_write.toml")
	if err := WriteClientConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "server_port = 45678") {
		t.Error("client config should contain server_port = 45678")
	}
	if strings.Contains(content, `server_port = "dynamic"`) {
		t.Error("client config should NOT contain server_port = \"dynamic\" for static port")
	}
}

// =============================================================================
// Enhanced Validation tests
// =============================================================================

func TestValidatePortSeedFormat(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.PortSeed = "not-hex!"
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "port_seed") {
			found = true
		}
	}
	if !found {
		t.Error("should report error for invalid hex port_seed")
	}
}

func TestValidatePortSeedTooShort(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.PortSeed = "abcd" // only 4 hex chars, need 16
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "port_seed") && strings.Contains(e, "short") {
			found = true
		}
	}
	if !found {
		t.Error("should report error for short port_seed")
	}
}

func TestValidatePortSeedValid(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.PortSeed = "abcdef0123456789"
	errs := cfg.Validate()
	for _, e := range errs {
		if strings.Contains(e, "port_seed") {
			t.Errorf("valid port_seed should not produce error: %s", e)
		}
	}
}

func TestValidateDefaultOpenDurationExceedsMax(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.DefaultOpenDuration = 100000
	cfg.MaxOpenDuration = 50000
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "default_open_duration") && strings.Contains(e, "exceeds") {
			found = true
		}
	}
	if !found {
		t.Error("should report error when default_open_duration > max_open_duration")
	}
}

func TestValidateSnifferMode(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.SnifferMode = "invalid_mode"
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "sniffer_mode") {
			found = true
		}
	}
	if !found {
		t.Error("should report error for invalid sniffer_mode")
	}
}

func TestValidateListenAddresses(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenAddresses = []string{"0.0.0.0", "not-an-ip"}
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "invalid listen address") {
			found = true
		}
	}
	if !found {
		t.Error("should report error for invalid listen address")
	}
}

func TestServerConfigNoStunServers(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 33333

	path := filepath.Join(t.TempDir(), "srv_no_stun.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	// Server config should NOT have STUN servers section
	if strings.Contains(content, "stun_servers") {
		t.Error("server config should NOT contain stun_servers (STUN is client-only)")
	}
}

// ========== Server Static Port Tests ==========

func TestServerStaticPortDisablesDynamic(t *testing.T) {
	tomlStr := `
listen_port = 21116
port_seed = "bdbacb8047d87d67"
dynamic_port_window = 60
dynamic_port_min = 10000
dynamic_port_max = 65000
sniffer_mode = "udp"
listen_addresses = ["0.0.0.0"]
`
	path := filepath.Join(t.TempDir(), "srv_static.toml")
	os.WriteFile(path, []byte(tomlStr), 0600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DynamicPort {
		t.Error("DynamicPort should be false when listen_port = 21116 (static port)")
	}
	if cfg.ListenPort != 21116 {
		t.Errorf("ListenPort = %d, want 21116", cfg.ListenPort)
	}
}

func TestServerDynamicPortWithSeed(t *testing.T) {
	tomlStr := `
listen_port = "dynamic"
port_seed = "bdbacb8047d87d67"
dynamic_port_window = 60
sniffer_mode = "udp"
listen_addresses = ["0.0.0.0"]
`
	path := filepath.Join(t.TempDir(), "srv_dynamic.toml")
	os.WriteFile(path, []byte(tomlStr), 0600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DynamicPort {
		t.Error("DynamicPort should be true when listen_port = \"dynamic\"")
	}
	if cfg.ListenPort != 0 {
		t.Errorf("ListenPort = %d, want 0 for dynamic", cfg.ListenPort)
	}
}

func TestServerImplicitDynamicFromSeed(t *testing.T) {
	// When listen_port = 0 (default) and port_seed is set, infer dynamic
	tomlStr := `
port_seed = "abcdef0123456789"
dynamic_port_window = 600
sniffer_mode = "udp"
`
	path := filepath.Join(t.TempDir(), "srv_implicit_dynamic.toml")
	os.WriteFile(path, []byte(tomlStr), 0600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DynamicPort {
		t.Error("DynamicPort should be true when port_seed is set and listen_port = 0")
	}
}

func TestServerStaticPortIgnoresSeed(t *testing.T) {
	// Even with port_seed present, a real listen_port should disable dynamic
	tomlStr := `
listen_port = 55000
port_seed = "abcdef0123456789"
dynamic_port_window = 60
sniffer_mode = "udp"
`
	path := filepath.Join(t.TempDir(), "srv_static_ignore_seed.toml")
	os.WriteFile(path, []byte(tomlStr), 0600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DynamicPort {
		t.Error("DynamicPort should be false when listen_port = 55000 even with port_seed")
	}
	if cfg.ListenPort != 55000 {
		t.Errorf("ListenPort = %d, want 55000", cfg.ListenPort)
	}
}

// ========== Export Settings Tests ==========

func TestServerConfigNoExportSettings(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenPort = 33333
	cfg.ExportEncrypted = true
	cfg.ExportPassword = "secret123"

	path := filepath.Join(t.TempDir(), "srv_no_export.toml")
	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if strings.Contains(content, "export_encrypted") {
		t.Error("server config should NOT contain export_encrypted")
	}
	if strings.Contains(content, "export_password") {
		t.Error("server config should NOT contain export_password")
	}
	if !strings.Contains(content, "Passwords should never be stored") {
		t.Error("should contain comment about not storing passwords")
	}
}

// ========== TOTP Validation Tests ==========

func TestValidateTOTPSecretValid(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "JBSWY3DPEHPK3PXP" // valid base32
	errs := cfg.Validate()
	for _, e := range errs {
		if strings.Contains(e, "totp_secret") {
			t.Errorf("valid TOTP secret should not produce error: %s", e)
		}
	}
}

func TestValidateTOTPSecretInvalidBase32(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "not-valid-base32!@#"
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "base32") {
			found = true
		}
	}
	if !found {
		t.Error("should report error for invalid base32 TOTP secret")
	}
}

func TestValidateTOTPSecretTooShort(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = true
	cfg.TOTPSecret = "ABCD"
	errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if strings.Contains(e, "too short") {
			found = true
		}
	}
	if !found {
		t.Error("should report error for short TOTP secret")
	}
}

func TestValidateTOTPDisabledNoValidation(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TOTPEnabled = false
	cfg.TOTPSecret = "garbage!!!"
	errs := cfg.Validate()
	for _, e := range errs {
		if strings.Contains(e, "totp") {
			t.Errorf("TOTP disabled should not validate secret: %s", e)
		}
	}
}

func TestSetConfigDirOverride(t *testing.T) {
	dir := t.TempDir()
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()

	SetConfigDir(dir)
	if ConfigDir() != dir {
		t.Errorf("ConfigDir() = %q, want %q", ConfigDir(), dir)
	}
}

func TestSetConfigDirCreatesDirectory(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "subdir", "config")
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()

	SetConfigDir(dir)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestConfigDirDefaultReturnsNonEmpty(t *testing.T) {
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()
	customConfigDir = ""

	d := ConfigDir()
	if d == "" {
		t.Error("ConfigDir() should not return empty string")
	}
}

func TestSetConfigDirAffectsServerConfigPath(t *testing.T) {
	dir := t.TempDir()
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()

	SetConfigDir(dir)
	want := filepath.Join(dir, "spk_server.toml")
	if got := ServerConfigPath(); got != want {
		t.Errorf("ServerConfigPath() = %q, want %q", got, want)
	}
}

func TestSetConfigDirAffectsClientConfigPath(t *testing.T) {
	dir := t.TempDir()
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()

	SetConfigDir(dir)
	want := filepath.Join(dir, "spk_client.toml")
	if got := ClientConfigPath(); got != want {
		t.Errorf("ClientConfigPath() = %q, want %q", got, want)
	}
}

func TestSetConfigDirAffectsStatePath(t *testing.T) {
	dir := t.TempDir()
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()

	SetConfigDir(dir)
	want := filepath.Join(dir, "state.json")
	if got := StatePath(); got != want {
		t.Errorf("StatePath() = %q, want %q", got, want)
	}
}

// TestConfigDirDefaultCreatesDirectory verifies that ConfigDir() always returns
// a path that exists on disk, even when no custom override is set.
// This is the root fix for the "system cannot find the path specified" error.
func TestConfigDirDefaultCreatesDirectory(t *testing.T) {
	origDir := customConfigDir
	defer func() { customConfigDir = origDir }()
	customConfigDir = ""

	dir := ConfigDir()
	if dir == "" {
		t.Fatal("ConfigDir() returned empty string")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("ConfigDir() returned %q but directory does not exist: %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("ConfigDir() returned %q but it is not a directory", dir)
	}
}

// TestWriteClientConfigCreatesParentDir verifies that WriteClientConfigWithComments
// creates any missing parent directories automatically (fixes client setup failure).
func TestWriteClientConfigCreatesParentDir(t *testing.T) {
	base := t.TempDir()
	// Use a nested path that doesn't exist yet
	dir := filepath.Join(base, "nested", "config")
	path := filepath.Join(dir, "spk_client.toml")

	cfg := DefaultClientConfig()
	cfg.ServerHost = "example.com"
	cfg.ServerPort = 12345

	if err := WriteClientConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteClientConfigWithComments failed on missing parent dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

// TestWriteServerConfigCreatesParentDir verifies that WriteServerConfigWithComments
// creates any missing parent directories automatically.
func TestWriteServerConfigCreatesParentDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "config")
	path := filepath.Join(dir, "spk_server.toml")

	cfg := DefaultServerConfig()

	if err := WriteServerConfigWithComments(path, cfg); err != nil {
		t.Fatalf("WriteServerConfigWithComments failed on missing parent dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

// TestSaveCreatesParentDir verifies that Config.Save creates any missing parent
// directories automatically.
func TestSaveCreatesParentDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "config")
	path := filepath.Join(dir, "state.json")

	cfg := DefaultServerConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save failed on missing parent dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("state file not created: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validate() additional edge cases
// ---------------------------------------------------------------------------

func TestValidateServerPortOutOfRange(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.ServerPort = -5
	errs := cfg.Validate()
	if !containsSubstring(errs, "server_port out of range") {
		t.Errorf("expected server_port error for -5, got: %v", errs)
	}
}

func TestValidateNegativeTimestampTolerance(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TimestampTolerance = -1
	errs := cfg.Validate()
	if !containsSubstring(errs, "timestamp_tolerance must be >= 0") {
		t.Errorf("expected timestamp_tolerance error, got: %v", errs)
	}
}

func TestValidateDynPortWindowNegative(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.DynPortWindow = -10
	errs := cfg.Validate()
	if !containsSubstring(errs, "dynamic_port_window must be >= 0") {
		t.Errorf("expected DynPortWindow error, got: %v", errs)
	}
}

func TestValidatePaddingMinNegative(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.PaddingEnabled = true
	cfg.PaddingMinBytes = -1
	cfg.PaddingMaxBytes = 100
	errs := cfg.Validate()
	if !containsSubstring(errs, "padding_min_bytes must be >= 0") {
		t.Errorf("expected negative padding_min error, got: %v", errs)
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.toml")
	os.WriteFile(path, []byte("{{{{not toml at all]]]]"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error loading invalid TOML")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Error("expected error loading nonexistent file")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Errorf("error should mention read config, got: %v", err)
	}
}

func TestValidateInvalidListenAddress(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ListenAddresses = []string{"not-an-ip"}
	errs := cfg.Validate()
	if !containsSubstring(errs, "invalid listen address") {
		t.Errorf("expected invalid listen address error, got: %v", errs)
	}
}

func TestValidateInvalidSnifferMode(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.SnifferMode = "invalid_mode"
	errs := cfg.Validate()
	if !containsSubstring(errs, "unknown sniffer_mode") {
		t.Errorf("expected sniffer_mode error, got: %v", errs)
	}
}

// containsSubstring checks if any string in the slice contains the substring.
func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
