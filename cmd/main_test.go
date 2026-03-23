package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xssnick/tonutils-storage-provider/config"
)

func TestCommitStartupWalletScanCursorOnSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := testMainConfig(t)
	cfg.StartupWalletScanLastLT = 10

	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	done := make(chan error, 1)
	commitStartupWalletScanCursorOnSuccess(path, cfg, 55, done)

	time.Sleep(50 * time.Millisecond)

	if got := readStartupWalletScanLastLT(t, path); got != 10 {
		t.Fatalf("cursor advanced before scan completion: got %d want 10", got)
	}

	done <- nil

	waitForStartupWalletScanLT(t, path, 55)
}

func TestCommitStartupWalletScanCursorOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := testMainConfig(t)
	cfg.StartupWalletScanLastLT = 10

	if err := config.SaveConfig(cfg, path); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	done := make(chan error, 1)
	commitStartupWalletScanCursorOnSuccess(path, cfg, 55, done)
	done <- errors.New("scan failed")

	time.Sleep(50 * time.Millisecond)

	if got := readStartupWalletScanLastLT(t, path); got != 10 {
		t.Fatalf("cursor advanced after failed scan: got %d want 10", got)
	}
}

func waitForStartupWalletScanLT(t *testing.T, path string, want uint64) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := readStartupWalletScanLastLT(t, path); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("cursor was not updated to %d in time", want)
}

func readStartupWalletScanLastLT(t *testing.T, path string) uint64 {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	return cfg.StartupWalletScanLastLT
}

func testMainConfig(t *testing.T) *config.Config {
	t.Helper()

	_, adnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate adnl key: %v", err)
	}

	_, providerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate provider key: %v", err)
	}

	return &config.Config{
		ADNLKey:           adnlKey,
		ProviderKey:       providerKey,
		ListenAddr:        "0.0.0.0:18555",
		ExternalIP:        "127.0.0.1",
		MinRatePerMBDay:   "0.0001",
		MinSpan:           600,
		MaxSpan:           86400,
		MaxBagSizeBytes:   1024,
		BagsDirForStorage: "./provider",
		Storages: []config.StorageConfig{
			{
				BaseURL:                 "http://127.0.0.1:9955",
				SpaceToProvideMegabytes: 1024,
			},
		},
	}
}
