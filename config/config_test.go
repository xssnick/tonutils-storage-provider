package config

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveConfigUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if err := SaveConfig(testConfig(t), path); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	if got := info.Mode().Perm(); got != privateConfigPerms {
		t.Fatalf("expected config perms %o, got %o", privateConfigPerms, got)
	}
}

func TestLoadConfigSecuresExistingFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	if err := SaveConfig(testConfig(t), path); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	if got := info.Mode().Perm(); got != privateConfigPerms {
		t.Fatalf("expected config perms %o after LoadConfig, got %o", privateConfigPerms, got)
	}
}

func testConfig(t *testing.T) *Config {
	t.Helper()

	_, adnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate adnl key: %v", err)
	}

	_, providerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate provider key: %v", err)
	}

	return &Config{
		ADNLKey:           adnlKey,
		ProviderKey:       providerKey,
		ListenAddr:        "0.0.0.0:18555",
		ExternalIP:        "127.0.0.1",
		MinRatePerMBDay:   "0.0001",
		MinSpan:           600,
		MaxSpan:           86400,
		MaxBagSizeBytes:   1024,
		BagsDirForStorage: "./provider",
		Storages: []StorageConfig{
			{
				BaseURL:                 "http://127.0.0.1:9955",
				SpaceToProvideMegabytes: 1024,
			},
		},
	}
}
