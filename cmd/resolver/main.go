package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-storage-provider/pkg/transport"
	"log"
	"time"
)

var adnlAddrHex = flag.String("adnl", "", "adnl address")
var providerPubHex = flag.String("provider", "", "provider pub key")

func main() {
	flag.Parse()

	var err error
	var adnlAddr []byte
	var providerKey []byte
	if *adnlAddrHex != "" {
		if len(*adnlAddrHex) != 64 {
			log.Fatalln("adnl address must be 32 bytes hex string, use -adnl flag")
			return
		}

		adnlAddr, err = hex.DecodeString(*adnlAddrHex)
		if err != nil {
			log.Fatalln("failed to decode adnl address:", err.Error())
		}
	} else {
		if len(*providerPubHex) != 64 {
			log.Fatalln("provider key must be 32 bytes hex string, use -provider flag")
			return
		}

		providerKey, err = hex.DecodeString(*providerPubHex)
		if err != nil {
			log.Fatalln("failed to decode provider key:", err.Error())
		}
	}

	_, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalln("failed to generate ed25519 key:", err.Error())
	}

	gw := adnl.NewGateway(prv)
	if err = gw.StartClient(); err != nil {
		log.Fatalln("failed to start adnl client:", err.Error())
	}

	log.Println("Starting DHT client...")
	cli, err := dht.NewClientFromConfigUrl(context.Background(), gw, "https://ton-blockchain.github.io/global.config.json")
	if err != nil {
		log.Fatalln("failed to create dht client:", err.Error())
	}

	if len(adnlAddr) == 0 {
		log.Println("Searching for provider in DHT...")
		channelKeyId, err := tl.Hash(keys.PublicKeyED25519{Key: providerKey})
		if err != nil {
			log.Fatalf("failed to calc hash of provider key %s: %v", hex.EncodeToString(providerKey), err)
		}

		dhtVal, _, err := cli.FindValue(context.Background(), &dht.Key{
			ID:    channelKeyId,
			Name:  []byte("storage-provider"),
			Index: 0,
		})
		if err != nil {
			log.Fatalf("failed to find storage-provider in dht of %s: %v", hex.EncodeToString(providerKey), err)
		}

		var nodeAddr transport.ProviderDHTRecord
		if _, err = tl.Parse(&nodeAddr, dhtVal.Data, true); err != nil {
			log.Fatalf("failed to parse node dht value of %s: %v", hex.EncodeToString(providerKey), err)
		}
		log.Println("Found provider adnl:", hex.EncodeToString(nodeAddr.ADNLAddr))
		adnlAddr = nodeAddr.ADNLAddr
	}

	log.Println("Searching for addresses in DHT...")
	addrList, pubKey, err := cli.FindAddresses(context.Background(), adnlAddr)
	if err != nil {
		if errors.Is(err, dht.ErrDHTValueIsNotFound) {
			log.Println("ADNL is not found in DHT")
			return
		}

		log.Fatalln("failed to find addresses:", err.Error())
	}

	log.Println("Resolved public key:", hex.EncodeToString(pubKey))
	log.Println("Found addresses", len(addrList.Addresses))

	for _, address := range addrList.Addresses {
		addr := address.IP.String() + ":" + fmt.Sprint(address.Port)
		log.Println("Found address:", addr, "checking ping...")

		peer, err := gw.RegisterClient(addr, pubKey)
		if err != nil {
			log.Println(addr, "Failed to register peer:", err.Error())
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := peer.Ping(ctx)
		if err != nil {
			log.Println(addr, "Ping failed:", err.Error())
			continue
		}
		cancel()

		log.Println("Available, ping to", addr, "is", p.String())
	}
	log.Println("Done")
}
