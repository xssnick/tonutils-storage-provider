package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/pkg/transport"
	"math/rand"
	"time"
)

func init() {
	tl.Register(TorrentInfoContainer{}, "storage.torrentInfo data:bytes = storage.TorrentInfo")
	tl.Register(GetTorrentInfo{}, "storage.getTorrentInfo = storage.TorrentInfo")
	tl.Register(Piece{}, "storage.piece proof:bytes data:bytes = storage.Piece")
	tl.Register(GetPiece{}, "storage.getPiece piece_id:int = storage.Piece")
	tl.Register(Ping{}, "storage.ping session_id:long = storage.Pong")
	tl.Register(Pong{}, "storage.pong = storage.Pong")
}

type Ping struct {
	SessionID int64 `tl:"long"`
}

type Pong struct{}

type TorrentInfoContainer struct {
	Data []byte `tl:"bytes"`
}

type GetTorrentInfo struct{}

type Piece struct {
	Proof []byte `tl:"bytes"`
	Data  []byte `tl:"bytes"`
}

type GetPiece struct {
	PieceID int32 `tl:"int"`
}

type TorrentInfo struct {
	PieceSize   uint32   `tlb:"## 32"`
	FileSize    uint64   `tlb:"## 64"`
	RootHash    []byte   `tlb:"bits 256"`
	HeaderSize  uint64   `tlb:"## 64"`
	HeaderHash  []byte   `tlb:"bits 256"`
	Description tlb.Text `tlb:"."`
}

var adnlAddrHex = flag.String("adnl", "", "adnl address")
var providerPubHex = flag.String("provider", "", "provider pub key")
var bagHex = flag.String("bag", "", "bag id")
var piece = flag.Int("piece", 0, "piece id")

func main() {
	flag.Parse()

	log.Logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger().Level(zerolog.InfoLevel)

	if *adnlAddrHex == "" && *providerPubHex == "" && *bagHex == "" {
		log.Fatal().Msg("adnl address, provider pub key or bag id must be specified, use -help for info")
		return
	}

	_, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate ed25519 key")
	}

	gw := adnl.NewGateway(prv)
	if err = gw.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("failed to start adnl client")
	}

	log.Info().Msg("Starting DHT client...")
	cli, err := dht.NewClientFromConfigUrl(context.Background(), gw, "https://ton-blockchain.github.io/global.config.json")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create dht client:")
	}

	var bag []byte
	var adnlAddrs [][]byte
	var providerKey []byte
	if *bagHex != "" {
		if len(*bagHex) != 64 {
			log.Fatal().Msg("bag id must be 32 bytes hex string")
			return
		}

		bag, err = hex.DecodeString(*bagHex)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to decode bag id")
			return
		}
	}

	if *adnlAddrHex != "" {
		if len(*adnlAddrHex) != 64 {
			log.Fatal().Msg("adnl address must be 32 bytes hex string, use -adnl flag")
			return
		}

		adnlAddr, err := hex.DecodeString(*adnlAddrHex)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to decode adnl address")
		}

		adnlAddrs = append(adnlAddrs, adnlAddr)
	}

	if *providerPubHex != "" {
		adnlAddrs = nil

		if len(*providerPubHex) != 64 {
			log.Fatal().Msg("provider key must be 32 bytes hex string, use -provider flag")
			return
		}

		providerKey, err = hex.DecodeString(*providerPubHex)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to decode provider key:")
		}

		log.Info().Msg("Searching for provider in DHT...")
		channelKeyId, err := tl.Hash(keys.PublicKeyED25519{Key: providerKey})
		if err != nil {
			log.Fatal().Msgf("failed to calc hash of provider key %s: %v", hex.EncodeToString(providerKey), err)
		}

		dhtVal, _, err := cli.FindValue(context.Background(), &dht.Key{
			ID:    channelKeyId,
			Name:  []byte("storage-provider"),
			Index: 0,
		})
		if err != nil {
			log.Fatal().Msgf("failed to find storage-provider in dht of %s: %v", hex.EncodeToString(providerKey), err)
		}

		var nodeAddr transport.ProviderDHTRecord
		if _, err = tl.Parse(&nodeAddr, dhtVal.Data, true); err != nil {
			log.Fatal().Msgf("failed to parse node dht value of %s: %v", hex.EncodeToString(providerKey), err)
		}
		log.Info().Msgf("Found provider adnl: %s", hex.EncodeToString(nodeAddr.ADNLAddr))
		adnlAddrs = append(adnlAddrs, nodeAddr.ADNLAddr)
	} else if *bagHex != "" {
		if len(adnlAddrs) == 0 {
			nodesList, _, err := cli.FindOverlayNodes(context.Background(), bag)
			if err != nil && !errors.Is(err, dht.ErrDHTValueIsNotFound) {
				log.Fatal().Err(err).Msg("failed to find bag overlay nodes")
				return
			}

			if nodesList == nil {
				log.Warn().Msg("no peers found for bag in DHT")
				return
			}

			for _, node := range nodesList.List {
				key, ok := node.ID.(keys.PublicKeyED25519)
				if !ok {
					continue
				}

				adnlID, err := tl.Hash(key)
				if err != nil {
					log.Fatal().Err(err).Msg("hash tl key error")
					return
				}

				adnlAddrs = append(adnlAddrs, adnlID)
			}
		}
	}

	if len(adnlAddrs) == 0 {
		log.Warn().Msg("no adnl addresses found")
		return
	}

	for i, addr := range adnlAddrs {
		println()
		log.Info().Msgf("Checking ADNL %d of %d", i+1, len(adnlAddrs))
		adnlCheck(cli, gw, addr, bag, int32(*piece))
	}

	log.Info().Msg("Done")
}

func adnlCheck(cli *dht.Client, gw *adnl.Gateway, adnlAddr []byte, bag []byte, pieceId int32) {
	log.Info().Msgf("Searching for ip addresses of %s ADNL in DHT...", hex.EncodeToString(adnlAddr))
	addrList, pubKey, err := cli.FindAddresses(context.Background(), adnlAddr)
	if err != nil {
		if errors.Is(err, dht.ErrDHTValueIsNotFound) {
			log.Warn().Msg("ADNL is not found in DHT (offline or client mode peer)")
			return
		}

		log.Fatal().Err(err).Msg("failed to find addresses")
		return
	}

	log.Info().Msgf("Resolved public key: %s", hex.EncodeToString(pubKey))
	log.Info().Msgf("Found %d addresses", len(addrList.Addresses))

	for _, address := range addrList.Addresses {
		addr := address.IP.String() + ":" + fmt.Sprint(address.Port)
		log.Info().Msgf("Found address %s checking ping...", addr)

		peer, err := gw.RegisterClient(addr, pubKey)
		if err != nil {
			log.Warn().Err(err).Str("addr", addr).Msg("Failed to register peer")
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := peer.Ping(ctx)
		cancel()
		if err != nil {
			log.Warn().Err(err).Str("addr", addr).Msg("Ping failed")
			continue
		}

		log.Info().Msgf("Available, ping to %s is %s", addr, p.String())

		if bag != nil {
			rl := rldp.NewClientV2(peer)

			over, err := tl.Hash(keys.PublicKeyOverlay{Key: bag})
			if err != nil {
				log.Warn().Err(err).Msg("failed to calc hash of bag overlay")
				continue
			}

			log.Info().Msg("Trying to init session for this bag with peer...")

			tm := time.Now()
			var pong Pong
			reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err = peer.Query(reqCtx, overlay.WrapQuery(over, &Ping{SessionID: rand.Int63()}), &pong)
			cancel()
			if err != nil {
				log.Warn().Err(err).Msg("failed to ping bag")
				continue
			}
			log.Info().Msgf("Session initialized, took: %s", time.Since(tm).String())

			log.Info().Msg("Trying to get bag info from peer...")

			var res TorrentInfoContainer
			reqCtx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
			err = rl.DoQuery(reqCtx, 32<<20, overlay.WrapQuery(over, &GetTorrentInfo{}), &res)
			cancel()
			if err != nil {
				log.Warn().Err(err).Msg("failed to get torrent info")
				continue
			}

			cl, err := cell.FromBOC(res.Data)
			if err != nil {
				log.Warn().Err(err).Msg("failed to parse torrent info cell")
				continue
			}

			if !bytes.Equal(cl.Hash(), bag) {
				log.Warn().Msg("incorrect torrent info hash")
				continue
			}

			var info TorrentInfo
			err = tlb.LoadFromCell(&info, cl.BeginParse())
			if err != nil {
				log.Warn().Err(err).Msg("failed to parse torrent info tlb")
				continue
			}

			log.Info().Msg("Torrent info acquired:")
			log.Info().Msgf("	Piece size: %d", info.PieceSize)
			log.Info().Msgf("	Bag size: %d", info.FileSize)
			log.Info().Msgf("	Header size: %d", info.HeaderSize)
			log.Info().Msgf("	Description: %s", info.Description.Value)
			log.Info().Msgf("Trying to get piece %d...", pieceId)

			time.Sleep(1 * time.Second)

			tm = time.Now()
			var piece Piece
			reqCtx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
			err = rl.DoQuery(reqCtx, 32<<20, overlay.WrapQuery(over, &GetPiece{pieceId}), &piece)
			cancel()
			if err != nil {
				log.Warn().Err(err).Msgf("Piece %d is not downloaded, error", pieceId)
				continue
			}

			log.Info().Msgf("Piece %d is downloaded in %s", pieceId, time.Since(tm).String())
		}
	}
}
