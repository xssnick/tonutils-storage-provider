package config

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"net"
	"os"
	"path/filepath"
	"time"
)

type StorageConfig struct {
	BaseURL                 string
	Login                   string
	Password                string
	SpaceToProvideMegabytes uint64
}

type Config struct {
	ADNLKey         ed25519.PrivateKey
	ProviderKey     ed25519.PrivateKey
	ListenAddr      string
	ExternalIP      string
	MinRatePerMBDay string
	MinSpan         uint32
	MaxSpan         uint32
	Storages        []StorageConfig
}

func checkIPAddress(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		log.Error().Int("len", len(p)).Msg("bad ip")
		return ""
	}
	p = p.To4()
	if p == nil {
		log.Error().Int("len", len(p)).Msg("bad ip, not v4")
		return ""
	}

	return p.String()
}

func checkCanSeed() (string, bool) {
	ch := make(chan bool, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip := ""
	go func() {
		defer func() {
			ch <- ip != ""
		}()

		listen, err := net.Listen("tcp", "0.0.0.0:18889")
		if err != nil {
			log.Error().Err(err).Msg("listen err")
			return
		}
		defer listen.Close()

		conn, err := listen.Accept()
		if err != nil {
			log.Error().Err(err).Msg("accept err")
			return
		}

		ipData := make([]byte, 256)
		n, err := conn.Read(ipData)
		if err != nil {
			log.Error().Err(err).Msg("read err")
			return
		}

		ip = string(ipData[:n])
		ip = checkIPAddress(ip)
		_ = conn.Close()
	}()

	log.Info().Str("at", "tonutils.com").Msg("Resolving port checker...")
	ips, err := net.LookupIP("tonutils.com")
	if err != nil || len(ips) == 0 {
		log.Warn().Str("at", "tonutils.com").Msg("port checker is not resolved, if you have external (white) ip, please set it manually in config file.")
		return "", false
	}
	log.Info().Str("at", "tonutils.com").Msg("port checker ip is resolved, using it to detect our availability from internet")

	conn, err := net.Dial("tcp", ips[0].String()+":9099")
	if err != nil {
		return "", false
	}

	_, err = conn.Write([]byte("ME"))
	if err != nil {
		return "", false
	}
	ok := false
	select {
	case k := <-ch:
		ok = k
		log.Info().Str("ip", ip).Msg("ports are open and available from internet")
	case <-ctx.Done():
		log.Warn().Msg("no request from port checker, looks like it cannot reach you, so ports are probably closed, if it is wrong and you have external (white) ip you could set it manually in config")
	}

	return ip, ok
}

func LoadConfig(path string) (*Config, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)
	_, err = os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err = os.MkdirAll(dir, os.ModePerm)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to check directory: %w", err)
		}
	}

	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		_, providerPrivate, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		cfg := &Config{
			ADNLKey:         private,
			ProviderKey:     providerPrivate,
			ListenAddr:      "0.0.0.0:18555",
			MinRatePerMBDay: "0.0001",
			MinSpan:         600,
			MaxSpan:         86400 * 2,
			Storages: []StorageConfig{
				{
					BaseURL:                 "http://127.0.0.1:17555",
					SpaceToProvideMegabytes: 32 * 1024,
				},
			},
		}

		ip, seed := checkCanSeed()
		if seed {
			cfg.ExternalIP = ip
		}

		err = SaveConfig(cfg, path)
		if err != nil {
			return nil, fmt.Errorf("failed to save config: %w", err)
		}

		return cfg, nil
	} else if err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}

		var cfg Config
		err = json.Unmarshal(data, &cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
		return &cfg, nil
	}
	println(path)

	return nil, err
}

func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, 0766)
	if err != nil {
		return err
	}
	return nil
}
