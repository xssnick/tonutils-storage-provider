package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-storage-provider/config"
	ldb "github.com/xssnick/tonutils-storage-provider/internal/db/leveldb"
	"github.com/xssnick/tonutils-storage-provider/internal/server"
	"github.com/xssnick/tonutils-storage-provider/internal/service"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
	dlog "log"
	"net"
)

var (
	ConfigPath        = flag.String("config", "./config.json", "Path to config file (.json)")
	DBPath            = flag.String("db", "./db", "Path to db")
	Verbosity         = flag.Int("verbosity", 0, "Debug logs")
	NetworkConfigPath = flag.String("network-config", "", "Network config path to load from disk")
)

func main() {
	flag.Parse()

	adnl.Logger = func(v ...any) {}
	dht.Logger = func(v ...any) {}

	if *Verbosity > 3 {
		*Verbosity = 3
	}

	log.Logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger().Level(zerolog.InfoLevel)

	switch *Verbosity {
	case 3:
		adnl.Logger = dlog.Println
		fallthrough
	case 2:
		dht.Logger = dlog.Println
		fallthrough
	case 1:
		log.Logger = log.Logger.Level(zerolog.DebugLevel).With().Logger()
	}

	cfg, err := config.LoadConfig(*ConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	db, err := ldb.NewDB(*DBPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load db")
	}

	var ip net.IP
	if cfg.ExternalIP != "" {
		ip = net.ParseIP(cfg.ExternalIP)
		if ip == nil {
			log.Fatal().Err(err).Msg("external ip is invalid")
		}
	} else {
		log.Fatal().Err(err).Msg("please set your external (public) ip in config")
	}

	var lsCfg *liteclient.GlobalConfig
	if *NetworkConfigPath != "" {
		lsCfg, err = liteclient.GetConfigFromFile(*NetworkConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to load ton network config from file")
		}
	} else {
		lsCfg, err = liteclient.GetConfigFromUrl(context.Background(), "https://ton.org/global.config.json")
		if err != nil {
			log.Warn().Err(err).Msg("failed to to download ton config, we will take it from static cache")

			lsCfg = &liteclient.GlobalConfig{}
			if err = json.NewDecoder(bytes.NewBufferString(config.FallbackNetworkConfig)).Decode(lsCfg); err != nil {
				log.Fatal().Err(err).Msg("failed to parse fallback ton config")
			}
		}
	}
	lc := liteclient.NewConnectionPool()
	if err = lc.AddConnectionsFromConfig(context.Background(), lsCfg); err != nil {
		log.Fatal().Err(err).Msg("failed to add liteserver connections from ton config")
	}

	gate := adnl.NewGateway(cfg.ADNLKey)
	gate.SetExternalIP(ip)

	err = gate.StartServer(cfg.ListenAddr)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start adnl gateway in server mode")
	}

	_, dhtPk, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate dht client private key")
	}

	dhtGate := adnl.NewGateway(dhtPk)
	if err = dhtGate.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("failed to init dht adnl gateway")
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGate, lsCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init dht client")
	}

	if len(cfg.Storages) == 0 {
		log.Fatal().Err(err).Msg("no storage instances provided")
	}

	// TODO: add support for multiple storages
	if len(cfg.Storages) != 1 {
		log.Fatal().Err(err).Msg("currently only one storage instance is supported")
	}

	stg := cfg.Storages[0]
	var cred *storage.Credentials
	if stg.Login != "" {
		cred = &storage.Credentials{
			Login:    stg.Login,
			Password: stg.Password,
		}
	}

	api := ton.NewAPIClient(lc).WithRetry(2)
	w, err := wallet.FromPrivateKey(api, cfg.ProviderKey, wallet.V3R2)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load wallet")
	}

	var balance = "???"
	master, err := api.CurrentMasterchainInfo(context.Background())
	if err != nil {
		log.Warn().Err(err).Msg("failed to get master block to check wallet balance")
	} else {
		bl, err := w.GetBalance(context.Background(), master)
		if err != nil {
			log.Warn().Err(err).Msg("failed to get wallet balance to check")
		}
		balance = bl.String()

		if bl.Nano().Cmp(tlb.MustFromTON("0.5").Nano()) < 0 {
			log.Warn().Str("balance", balance+" TON").Msg("wallet balance is low, topup it")
		}
	}

	log.Info().Str("address", w.WalletAddress().String()).Str("balance", balance+" TON").Msg("provider wallet initialized")

	svc, err := service.NewService(
		api,
		storage.NewClient(stg.BaseURL, cred),
		db,
		cfg.ProviderKey,
		w,
		tlb.MustFromTON(cfg.MinRatePerMBDay),
		stg.SpaceToProvideMegabytes<<20, cfg.MaxBagSizeBytes,
		cfg.MinSpan, cfg.MaxSpan,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init service")
	}

	server.NewServer(dhtClient, gate, cfg.ADNLKey, cfg.ProviderKey, svc, log.Logger.With().Str("source", "server").Logger())

	log.Info().Hex("provider_key", cfg.ProviderKey.Public().(ed25519.PublicKey)).Msg("service started")

	<-make(chan bool)
}
