package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	tonaddress "github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tl"
	"sync"
	"time"
)

type providerPeer struct {
	rldp *rldp.RLDP
	conn adnl.Peer

	mx sync.Mutex
}

type DHT interface {
	FindAddresses(ctx context.Context, key []byte) (*address.List, ed25519.PublicKey, error)
	FindValue(ctx context.Context, key *dht.Key, continuation ...*dht.Continuation) (*dht.Value, *dht.Continuation, error)
}

type Client struct {
	dht  DHT
	gate *adnl.Gateway

	active map[string]*providerPeer

	mx sync.Mutex
}

func NewClient(gate *adnl.Gateway, dht DHT) *Client {
	return &Client{gate: gate, dht: dht, active: map[string]*providerPeer{}}
}

func (c *Client) connect(ctx context.Context, providerKey []byte) (*providerPeer, error) {
	c.mx.Lock()
	p := c.active[string(providerKey)]
	if p == nil {
		p = &providerPeer{}
		c.active[string(providerKey)] = p
	}
	c.mx.Unlock()

	p.mx.Lock()
	defer p.mx.Unlock()

	if p.conn != nil {
		return p, nil
	}

	channelKeyId, err := tl.Hash(adnl.PublicKeyED25519{Key: providerKey})
	if err != nil {
		return nil, fmt.Errorf("failed to calc hash of provider key %s: %w", hex.EncodeToString(providerKey), err)
	}

	dhtVal, _, err := c.dht.FindValue(ctx, &dht.Key{
		ID:    channelKeyId,
		Name:  []byte("storage-provider"),
		Index: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to find storage-provider in dht of %s: %w", hex.EncodeToString(providerKey), err)
	}

	var nodeAddr ProviderDHTRecord
	if _, err = tl.Parse(&nodeAddr, dhtVal.Data, true); err != nil {
		return nil, fmt.Errorf("failed to parse node dht value of %s: %w", hex.EncodeToString(providerKey), err)
	}

	list, key, err := c.dht.FindAddresses(ctx, nodeAddr.ADNLAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to find address in dht of %s: %w", hex.EncodeToString(providerKey), err)
	}

	if len(list.Addresses) == 0 {
		return nil, fmt.Errorf("no addresses for %s", hex.EncodeToString(providerKey))
	}
	addr := fmt.Sprintf("%s:%d", list.Addresses[0].IP.String(), list.Addresses[0].Port)

	peer, err := c.gate.RegisterClient(addr, key)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer of %s at %s: %w", hex.EncodeToString(providerKey), addr, err)
	}

	peer.SetDisconnectHandler(func(addr string, _ ed25519.PublicKey) {
		c.mx.Lock()
		defer c.mx.Unlock()

		delete(c.active, string(providerKey))
	})

	p.rldp = rldp.NewClientV2(peer)
	p.conn = peer

	return p, nil
}

func (c *Client) GetStorageRates(ctx context.Context, provider []byte, size uint64) (*StorageRatesResponse, error) {
	p, err := c.connect(ctx, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to provider: %w", err)
	}

	now := time.Now()
	var res StorageRatesResponse
	if err = p.rldp.DoQuery(ctx, 8196, StorageRatesRequest{Size: size}, &res); err != nil {
		if time.Since(now) > 3*time.Second {
			// consider it as timeout and stuck connection
			p.conn.Close()
		}
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	return &res, nil
}

func (c *Client) RequestStorageInfo(ctx context.Context, provider []byte, contractAddr *tonaddress.Address, byteToProof uint64) (*StorageResponse, error) {
	p, err := c.connect(ctx, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to provider: %w", err)
	}

	now := time.Now()
	var res StorageResponse
	if err = p.rldp.DoQuery(ctx, 1024*64, StorageRequest{
		ContractAddress: contractAddr.Data(),
		ByteToProof:     byteToProof,
	}, &res); err != nil {
		if time.Since(now) > 10*time.Second {
			// consider it as timeout and stuck connection
			p.conn.Close()
		}
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	return &res, nil
}

func (c *Client) VerifyStorageADNLProof(ctx context.Context, provider []byte, contract *tonaddress.Address) ([]byte, error) {
	p, err := c.connect(ctx, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to provider: %w", err)
	}

	var res StorageADNLProofResponse
	if err = p.rldp.DoQuery(ctx, 8196, StorageADNLProofRequest{ContractAddress: contract.Data()}, &res); err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}

	sr, err := tl.Serialize(ADNLProofScheme{
		Key: provider,
	}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize provider id, invalid result")
	}

	if !ed25519.Verify(res.StorageKey, sr, res.Signature) {
		return nil, fmt.Errorf("failed to verify provider adnl, invalid result")
	}

	adnlId, err := tl.Hash(adnl.PublicKeyED25519{Key: res.StorageKey})
	if err != nil {
		return nil, fmt.Errorf("failed to calc hash of storage key %s: %w", hex.EncodeToString(res.StorageKey), err)
	}

	return adnlId, nil
}
