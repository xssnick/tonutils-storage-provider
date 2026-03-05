package service

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-storage-provider/config"
)

const startupScanKnownMainnetAddr = "EQAHWJ_gHBun5EPnRITZkQln1zNWYPFLzzM1WLXUN3ah2e6v"

type mainnetFetchStorageInfoStub struct {
	t     *testing.T
	calls []startupFetchCall
}

func (s *mainnetFetchStorageInfoStub) FetchStorageInfo(ctx context.Context, contractAddr *address.Address, byteToProof uint64) (*StorageInfo, error) {
	if s.t != nil {
		s.t.Logf("mainnet startup scan FetchStorageInfo call: addr=%s byteToProof=%d", contractAddr.String(), byteToProof)
	}

	deadline, ok := ctx.Deadline()
	call := startupFetchCall{
		addr:        contractAddr.String(),
		byteToProof: byteToProof,
		hasDeadline: ok,
	}
	if ok {
		call.timeout = time.Until(deadline)
	}
	s.calls = append(s.calls, call)

	return &StorageInfo{Status: "stub"}, nil
}

func TestScanWalletTransactions_Mainnet_NoBlockchainMocks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mainnet integration test in short mode")
	}

	ctx := context.Background()

	lsCfg, err := liteclient.GetConfigFromUrl(ctx, "https://ton.org/global.config.json")
	if err != nil {
		t.Logf("failed to download ton config, using fallback: %v", err)
		lsCfg = &liteclient.GlobalConfig{}
		if decErr := json.NewDecoder(bytes.NewBufferString(config.FallbackNetworkConfig)).Decode(lsCfg); decErr != nil {
			t.Fatalf("failed to parse fallback config: %v", decErr)
		}
	}

	lc := liteclient.NewConnectionPool()
	if err = lc.AddConnectionsFromConfig(ctx, lsCfg); err != nil {
		t.Fatalf("failed to connect to liteservers: %v", err)
	}

	api := ton.NewAPIClient(lc).WithRetry(2).WithLSInfoInErrors()
	walletAddr := address.MustParseAddr(startupScanKnownMainnetAddr)

	master, err := api.CurrentMasterchainInfo(ctx)
	if err != nil {
		t.Fatalf("failed to get masterchain info: %v", err)
	}

	acc, err := api.WaitForBlock(master.SeqNo).GetAccount(ctx, master, walletAddr)
	if err != nil {
		t.Fatalf("failed to get wallet account: %v", err)
	}
	if acc == nil || !acc.IsActive || acc.LastTxLT == 0 || len(acc.LastTxHash) == 0 {
		t.Fatalf("wallet has no scannable tx cursor: active=%v lt=%d hash_len=%d", acc != nil && acc.IsActive, acc.LastTxLT, len(acc.LastTxHash))
	}

	fetcher := &mainnetFetchStorageInfoStub{t: t}
	scanWalletTransactions(ctx, walletAddr, acc.LastTxLT, acc.LastTxHash, 0, api.ListTransactions, fetcher)

	if len(fetcher.calls) == 0 {
		t.Fatalf("expected at least one FetchStorageInfo call from real mainnet scan for wallet %s", walletAddr.String())
	}

	for _, call := range fetcher.calls {
		if call.byteToProof != 0 {
			t.Fatalf("expected byteToProof=0, got %d", call.byteToProof)
		}
		if !call.hasDeadline {
			t.Fatal("expected FetchStorageInfo context to have deadline")
		}
		if call.timeout <= 0 || call.timeout > startupWalletFetchTimeout {
			t.Fatalf("expected timeout in (0,%s], got %s", startupWalletFetchTimeout, call.timeout)
		}
	}
}
