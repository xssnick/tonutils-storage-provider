package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	base        string
	client      http.Client
	credentials *Credentials
}

type Credentials struct {
	Login    string
	Password string
}

var ErrNotFound = errors.New("not found")

func NewClient(base string, credentials *Credentials) *Client {
	return &Client{
		base: base,
		client: http.Client{
			Timeout: 15 * time.Second,
		},
		credentials: credentials,
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
		Path:        "./provider",
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
