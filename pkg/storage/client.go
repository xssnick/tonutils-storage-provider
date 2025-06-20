package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-storage-provider/pkg/transport"
	"net/http"
	"time"
)

type Client struct {
	providerId  []byte
	base        string
	rootPath    string
	client      http.Client
	credentials *Credentials
}

type Credentials struct {
	Login    string
	Password string
}

var ErrNotFound = errors.New("not found")

func NewClient(base, rootPath string, providerId []byte, credentials *Credentials) *Client {
	return &Client{
		base:     base,
		rootPath: rootPath,
		client: http.Client{
			Timeout: 15 * time.Second,
		},
		credentials: credentials,
		providerId:  providerId,
	}
}

func (c *Client) GetBag(ctx context.Context, bagId []byte) (*BagDetailed, error) {
	var res BagDetailed
	if err := c.doRequest(ctx, "GET", "/api/v1/details?bag_id="+hex.EncodeToString(bagId), nil, &res); err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}

	if res.InfoLoaded && res.MerkleHash == "" {
		return nil, fmt.Errorf("too old tonutils-storage version, please update")
	}
	return &res, nil
}

func (c *Client) GetPieceProof(ctx context.Context, bagId []byte, piece uint64) ([]byte, error) {
	var res ProofResponse
	if err := c.doRequest(ctx, "GET", "/api/v1/piece/proof?bag_id="+hex.EncodeToString(bagId)+"&piece="+fmt.Sprint(piece), nil, &res); err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	return res.Proof, nil
}

func (c *Client) StartDownload(ctx context.Context, bagId []byte, downloadAll bool) error {
	type request struct {
		BagID       string   `json:"bag_id"`
		Path        string   `json:"path"`
		DownloadAll bool     `json:"download_all"`
		Files       []uint32 `json:"files"`
	}

	var res Result
	if err := c.doRequest(ctx, "POST", "/api/v1/add", request{
		BagID:       hex.EncodeToString(bagId),
		Path:        c.rootPath,
		DownloadAll: downloadAll,
	}, &res); err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}

	if !res.Ok {
		return fmt.Errorf("error in response: %s", res.Error)
	}
	return nil
}

func (c *Client) RemoveBag(ctx context.Context, bagId []byte, withFiles bool) error {
	type request struct {
		BagID     string `json:"bag_id"`
		WithFiles bool   `json:"with_files"`
	}

	var res Result
	if err := c.doRequest(ctx, "POST", "/api/v1/remove", request{
		BagID:     hex.EncodeToString(bagId),
		WithFiles: withFiles,
	}, &res); err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}

	if !res.Ok {
		return fmt.Errorf("error in response: %s", res.Error)
	}
	return nil
}

func (c *Client) doRequest(ctx context.Context, method, url string, req, resp any) error {
	buf := &bytes.Buffer{}
	if req != nil {
		if err := json.NewEncoder(buf).Encode(req); err != nil {
			return fmt.Errorf("failed to encode request data: %w", err)
		}
	}

	r, err := http.NewRequestWithContext(ctx, method, c.base+url, buf)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	if c.credentials != nil {
		r.SetBasicAuth(c.credentials.Login, c.credentials.Password)
	}

	res, err := c.client.Do(r)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		return ErrNotFound
	}

	if res.StatusCode != 200 {
		var e Result
		if err = json.NewDecoder(res.Body).Decode(&e); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
		return fmt.Errorf("status code is %d, error: %s", res.StatusCode, e.Error)
	}

	if err = json.NewDecoder(res.Body).Decode(resp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func (c *Client) ProofProvider(ctx context.Context) (ed25519.PublicKey, []byte, error) {
	type request struct {
		ProviderID string `json:"provider_id"`
	}

	var res ADNLProofResponse
	if err := c.doRequest(ctx, "POST", "/api/v1/sign/provider", request{
		ProviderID: hex.EncodeToString(c.providerId),
	}, &res); err != nil {
		return nil, nil, fmt.Errorf("failed to do request: %w", err)
	}

	sr, err := tl.Serialize(transport.ADNLProofScheme{
		Key: c.providerId,
	}, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize provider id, invalid result")
	}

	if !ed25519.Verify(res.Key, sr, res.Signature) {
		return nil, nil, fmt.Errorf("failed to sign provider id, invalid result")
	}
	return res.Key, res.Signature, nil
}
