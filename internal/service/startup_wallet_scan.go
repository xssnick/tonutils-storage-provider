package service

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
)

const (
	startupWalletScanOpcode    = uint64(0xa91baf56)
	startupWalletScanBatchSize = uint32(20)
	startupWalletFetchTimeout  = 15 * time.Second
	startupWalletByteToProof   = uint64(0)
)

type storageInfoFetcher interface {
	FetchStorageInfo(ctx context.Context, contractAddr *address.Address, byteToProof uint64) (*StorageInfo, error)
}

type listTransactionsFn func(ctx context.Context, addr *address.Address, num uint32, lt uint64, txHash []byte) ([]*tlb.Transaction, error)

func (s *Service) StartWalletStartupScan(ctx context.Context, scanAPI ton.APIClientWrapped, startLT uint64, startHash []byte, stopLT uint64) <-chan error {
	done := make(chan error, 1)
	if s == nil || s.wallet == nil || scanAPI == nil {
		done <- nil
		close(done)
		return done
	}

	go func() {
		done <- scanWalletTransactions(ctx, s.wallet.WalletAddress(), startLT, startHash, stopLT, scanAPI.ListTransactions, s)
		close(done)
	}()
	return done
}

func scanWalletTransactions(
	ctx context.Context,
	walletAddr *address.Address,
	startLT uint64,
	startHash []byte,
	stopLT uint64,
	listFn listTransactionsFn,
	fetcher storageInfoFetcher,
) error {
	if walletAddr == nil || startLT == 0 || len(startHash) == 0 || listFn == nil || fetcher == nil {
		return nil
	}

	seen := map[string]struct{}{}
	lt := startLT
	hash := append([]byte(nil), startHash...)

	num := 0
	log.Info().
		Str("addr", walletAddr.String()).
		Uint64("from_lt", startLT).
		Uint64("stop_lt", stopLT).
		Msg("scanning wallet transactions")
	defer log.Info().
		Str("addr", walletAddr.String()).
		Uint64("last_cursor_lt", lt).
		Uint64("stop_lt", stopLT).
		Int("tx_count", num).
		Msg("wallet transactions scan finished")

	for {
		txs, err := listFn(ctx, walletAddr, startupWalletScanBatchSize, lt, hash)
		if err != nil {
			if errors.Is(err, ton.ErrNoTransactionsWereFound) {
				return nil
			}
			log.Warn().Err(err).Uint64("lt", lt).Msg("failed to list wallet transactions during startup scan")
			return err
		}

		if len(txs) == 0 {
			return nil
		}

		for i := len(txs) - 1; i >= 0; i-- {
			tx := txs[i]
			if tx == nil {
				continue
			}
			if stopLT > 0 && tx.LT <= stopLT {
				return nil
			}

			processStartupWalletScanTx(ctx, tx, seen, fetcher)
			num++
		}

		oldest := txs[0]
		if oldest == nil || oldest.PrevTxLT == 0 || len(oldest.PrevTxHash) == 0 {
			return nil
		}

		lt = oldest.PrevTxLT
		hash = append([]byte(nil), oldest.PrevTxHash...)
	}
}

func processStartupWalletScanTx(ctx context.Context, tx *tlb.Transaction, seen map[string]struct{}, fetcher storageInfoFetcher) {
	if tx == nil || tx.IO.In == nil || tx.IO.In.MsgType != tlb.MsgTypeInternal {
		return
	}

	in := tx.IO.In.AsInternal()
	if in == nil || in.SrcAddr == nil || in.Body == nil {
		return
	}

	op, err := in.Body.BeginParse().LoadUInt(32)
	if err != nil || op != startupWalletScanOpcode {
		return
	}

	addr := in.SrcAddr.String()
	if _, ok := seen[addr]; ok {
		return
	}
	seen[addr] = struct{}{}

	cCtx, cancel := context.WithTimeout(ctx, startupWalletFetchTimeout)
	_, err = fetcher.FetchStorageInfo(cCtx, in.SrcAddr, startupWalletByteToProof)
	cancel()
	if err != nil {
		log.Debug().Err(err).Str("addr", addr).Uint64("lt", tx.LT).Msg("failed to fetch storage info from startup wallet scan")
	}
}
