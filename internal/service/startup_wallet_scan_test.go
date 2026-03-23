package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/pkg/contract"
)

const startupScanUnitFakeAddr = "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c"

type startupFetchCall struct {
	addr        string
	byteToProof uint64
	hasDeadline bool
	timeout     time.Duration
}

type startupFetchStorageInfoStub struct {
	t     *testing.T
	calls []startupFetchCall
}

func (s *startupFetchStorageInfoStub) FetchStorageInfo(ctx context.Context, contractAddr *address.Address, byteToProof uint64) (*StorageInfo, error) {
	if s.t != nil {
		s.t.Logf("startup scan FetchStorageInfo call: addr=%s byteToProof=%d", contractAddr.String(), byteToProof)
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

	return nil, errors.New("expected test error")
}

func TestScanWalletTransactions_FiltersOpcodeDedupsSendersAndCallsFetchStorageInfo(t *testing.T) {
	walletAddr := address.MustParseAddr(startupScanUnitFakeAddr)
	senderA := address.MustParseAddr(startupScanUnitFakeAddr)
	senderB := contract.DiscoveryAddr

	startLT := uint64(500)
	startHash := []byte{0x05}

	batch1 := []*tlb.Transaction{
		buildInternalTx(480, 400, []byte{0x04}, senderA, startupWalletScanOpcode),
		buildInternalTx(490, 0, nil, senderA, startupWalletScanOpcode), // duplicate sender
		buildInternalTx(500, 0, nil, senderB, 0x11223344),              // wrong opcode
	}
	batch2 := []*tlb.Transaction{
		buildInternalTx(350, 300, []byte{0x03}, senderB, startupWalletScanOpcode),
		buildMalformedBodyTx(360, 0, nil, senderA), // no 32 bits in body
		buildExternalTx(370),
	}

	listCalls := 0
	listFn := func(_ context.Context, addr *address.Address, num uint32, lt uint64, txHash []byte) ([]*tlb.Transaction, error) {
		listCalls++

		if addr.String() != walletAddr.String() {
			t.Fatalf("unexpected wallet addr: %s", addr.String())
		}
		if num != startupWalletScanBatchSize {
			t.Fatalf("unexpected batch size: %d", num)
		}

		switch listCalls {
		case 1:
			if lt != 500 || !bytes.Equal(txHash, []byte{0x05}) {
				t.Fatalf("unexpected cursor on first page: lt=%d hash=%x", lt, txHash)
			}
			return batch1, nil
		case 2:
			if lt != 400 || !bytes.Equal(txHash, []byte{0x04}) {
				t.Fatalf("unexpected cursor on second page: lt=%d hash=%x", lt, txHash)
			}
			return batch2, nil
		case 3:
			if lt != 300 || !bytes.Equal(txHash, []byte{0x03}) {
				t.Fatalf("unexpected cursor on third page: lt=%d hash=%x", lt, txHash)
			}
			return nil, ton.ErrNoTransactionsWereFound
		default:
			t.Fatalf("unexpected extra list call #%d", listCalls)
		}

		return nil, nil
	}

	fetcher := &startupFetchStorageInfoStub{t: t}
	if err := scanWalletTransactions(context.Background(), walletAddr, startLT, startHash, 0, listFn, fetcher); err != nil {
		t.Fatalf("scan returned error: %v", err)
	}

	if listCalls != 3 {
		t.Fatalf("expected 3 list calls, got %d", listCalls)
	}
	if len(fetcher.calls) != 2 {
		t.Fatalf("expected 2 fetch calls, got %d", len(fetcher.calls))
	}

	if fetcher.calls[0].addr != senderA.String() {
		t.Fatalf("unexpected first fetch addr: %s", fetcher.calls[0].addr)
	}
	if fetcher.calls[1].addr != senderB.String() {
		t.Fatalf("unexpected second fetch addr: %s", fetcher.calls[1].addr)
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

func buildInternalTx(lt, prevLT uint64, prevHash []byte, src *address.Address, op uint64) *tlb.Transaction {
	tx := &tlb.Transaction{
		LT:         lt,
		PrevTxLT:   prevLT,
		PrevTxHash: prevHash,
	}
	tx.IO.In = &tlb.Message{
		MsgType: tlb.MsgTypeInternal,
		Msg: &tlb.InternalMessage{
			SrcAddr: src,
			Body: cell.BeginCell().
				MustStoreUInt(op, 32).
				EndCell(),
		},
	}
	return tx
}

func buildMalformedBodyTx(lt, prevLT uint64, prevHash []byte, src *address.Address) *tlb.Transaction {
	tx := &tlb.Transaction{
		LT:         lt,
		PrevTxLT:   prevLT,
		PrevTxHash: prevHash,
	}
	tx.IO.In = &tlb.Message{
		MsgType: tlb.MsgTypeInternal,
		Msg: &tlb.InternalMessage{
			SrcAddr: src,
			Body:    cell.BeginCell().EndCell(),
		},
	}
	return tx
}

func buildExternalTx(lt uint64) *tlb.Transaction {
	tx := &tlb.Transaction{
		LT: lt,
	}
	tx.IO.In = &tlb.Message{
		MsgType: tlb.MsgTypeExternalIn,
		Msg:     &tlb.ExternalMessage{},
	}
	return tx
}
