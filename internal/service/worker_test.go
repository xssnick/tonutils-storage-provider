package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
)

type workerTONStub struct {
	ton.APIClientWrapped
	storageInfo *ton.ExecutionResult
}

func (s workerTONStub) CurrentMasterchainInfo(context.Context) (*ton.BlockIDExt, error) {
	return &ton.BlockIDExt{}, nil
}

func (s workerTONStub) RunGetMethod(context.Context, *ton.BlockIDExt, *address.Address, string, ...any) (*ton.ExecutionResult, error) {
	return s.storageInfo, nil
}

type workerGetBagStub struct {
	Storage
	getBag func() (*storage.BagDetailed, error)
}

func (s workerGetBagStub) GetBag(context.Context, []byte) (*storage.BagDetailed, error) {
	return s.getBag()
}

func TestBagWorkerRegistersLegacyAddedBagBeforeAccessingStorage(t *testing.T) {
	contractAddr := address.MustParseAddr(testContractAddr(1))
	stored := db.StoredBag{ContractAddr: contractAddr.String(), Status: db.StoredBagStatusAdded}
	xdb := newMemoryContractDB(stored)
	bagID := bytes.Repeat([]byte{0x11}, 32)
	const size = 100
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	svc := &Service{
		db:        xdb,
		globalCtx: ctx,
		ton: workerTONStub{storageInfo: ton.NewExecutionResult([]any{
			new(big.Int).SetBytes(bagID), big.NewInt(size), big.NewInt(128),
			cell.BeginCell().MustStoreAddr(contractAddr).EndCell().MustBeginParse(), big.NewInt(0),
		})},
		storage: workerGetBagStub{getBag: func() (*storage.BagDetailed, error) {
			defer cancel()
			got, err := xdb.GetContract(stored.ContractAddr)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != db.StoredBagStatusAdded || !bytes.Equal(got.BagID, bagID) || got.Size != size {
				t.Fatalf("expected resolved Added record before GetBag, got %+v", got)
			}
			return nil, context.Canceled
		}},
	}

	svc.bagWorker(contractAddr, stored)
}

type cleanupStorageStub struct {
	*storage.Client
	path        string
	removeErr   error
	getCalls    int
	removeCalls int
	removed     bool
	removedID   []byte
	withFiles   bool
}

func (s *cleanupStorageStub) GetBag(_ context.Context, _ []byte) (*storage.BagDetailed, error) {
	s.getCalls++
	if s.removed {
		return nil, storage.ErrNotFound
	}
	return &storage.BagDetailed{Path: s.path}, nil
}

func (s *cleanupStorageStub) RemoveBag(_ context.Context, bagID []byte, withFiles bool) error {
	s.removeCalls++
	s.removed = s.removeErr == nil
	s.removedID = bagID
	s.withFiles = withFiles
	return s.removeErr
}

func TestStopBagContractChecksPathAndReferences(t *testing.T) {
	bagID := bytes.Repeat([]byte{0x11}, 32)
	bagHex := hex.EncodeToString(bagID)
	otherBagID := bytes.Repeat([]byte{0x22}, 32)
	managedPath := filepath.Join("provider", bagHex)
	customRoot := t.TempDir()
	customPath := filepath.Join(customRoot, bagHex)
	foreignPath := filepath.Join(t.TempDir(), "provider", bagHex)
	addr := testContractAddr(1)
	otherAddr := testContractAddr(2)

	tests := []struct {
		name       string
		root       string
		path       string
		other      *db.StoredBag
		wantRemove bool
	}{
		{name: "normalized default path", root: "./provider", path: managedPath, wantRemove: true},
		{name: "legacy default path", root: "./provider", path: "./provider/" + bagHex, wantRemove: true},
		{name: "configured absolute path", root: customRoot + string(filepath.Separator), path: customPath, wantRemove: true},
		{name: "same suffix in another directory", root: "./provider", path: foreignPath},
		{name: "wrong bag id in configured directory", root: "./provider", path: filepath.Join("provider", hex.EncodeToString(otherBagID))},
		{name: "missing path", root: "./provider"},
		{name: "empty configured root", path: bagHex},
		{
			name: "another active contract", root: "./provider", path: managedPath,
			other: &db.StoredBag{ContractAddr: otherAddr, BagID: bagID, Status: db.StoredBagStatusActive},
		},
		{
			name: "another added contract", root: "./provider", path: managedPath,
			other: &db.StoredBag{ContractAddr: otherAddr, BagID: bagID, Status: db.StoredBagStatusAdded},
		},
		{
			name: "added contract for another bag", root: "./provider", path: managedPath,
			other:      &db.StoredBag{ContractAddr: otherAddr, BagID: otherBagID, Status: db.StoredBagStatusAdded},
			wantRemove: true,
		},
		{
			name: "another stopped contract", root: "./provider", path: managedPath,
			other:      &db.StoredBag{ContractAddr: otherAddr, BagID: bagID, Status: db.StoredBagStatusStopped},
			wantRemove: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xdb := newMemoryContractDB(db.StoredBag{ContractAddr: addr, BagID: bagID, Status: db.StoredBagStatusActive})
			if tt.other != nil {
				if err := xdb.SetContract(*tt.other); err != nil {
					t.Fatal(err)
				}
			}
			stg := &cleanupStorageStub{Client: storage.NewClient("", tt.root, nil, nil), path: tt.path}
			svc := &Service{db: xdb, storage: stg}
			reason := db.StoredBagStopReasonProviderRemoved

			if err := svc.stopBagContract(t.Context(), addr, bagID, nil, reason); err != nil {
				t.Fatal(err)
			}
			if tt.wantRemove {
				if stg.removeCalls != 1 || !bytes.Equal(stg.removedID, bagID) || !stg.withFiles {
					t.Fatalf("expected one removal of bag %x with files, got %d calls, bag %x, withFiles=%t", bagID, stg.removeCalls, stg.removedID, stg.withFiles)
				}
			} else if stg.removeCalls != 0 {
				t.Fatalf("unexpected removals: %d", stg.removeCalls)
			}
			stopped, err := xdb.GetContract(addr)
			if err != nil {
				t.Fatal(err)
			}
			if stopped.Status != db.StoredBagStatusStopped || stopped.StopReason != reason {
				t.Fatalf("unexpected stopped contract: %+v", stopped)
			}
			if tt.other != nil {
				other, err := xdb.GetContract(otherAddr)
				if err != nil {
					t.Fatal(err)
				}
				if other.Status != tt.other.Status {
					t.Fatalf("other contract status = %v, want %v", other.Status, tt.other.Status)
				}
			}
		})
	}
}

func TestStopBagContractConcurrentStopsRemoveOnce(t *testing.T) {
	bagID := make([]byte, 32)
	firstAddr, secondAddr := testContractAddr(1), testContractAddr(2)
	xdb := newMemoryContractDB(
		db.StoredBag{ContractAddr: firstAddr, BagID: bagID, Status: db.StoredBagStatusActive},
		db.StoredBag{ContractAddr: secondAddr, BagID: bagID, Status: db.StoredBagStatusAdded},
	)
	stg := &cleanupStorageStub{
		Client: storage.NewClient("", "./provider", nil, nil),
		path:   filepath.Join("provider", hex.EncodeToString(bagID)),
	}
	svc := &Service{db: xdb, storage: stg}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, addr := range []string{firstAddr, secondAddr} {
		go func() {
			<-start
			results <- svc.stopBagContract(t.Context(), addr, bagID, nil, db.StoredBagStopReasonProviderRemoved)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if stg.getCalls != 1 || stg.removeCalls != 1 {
		t.Fatalf("expected only the last stop to reach storage, got %d reads and %d removals", stg.getCalls, stg.removeCalls)
	}
}

func TestStopBagContractRetriesFailedRemoval(t *testing.T) {
	bagID := make([]byte, 32)
	addr := testContractAddr(1)
	xdb := newMemoryContractDB(db.StoredBag{ContractAddr: addr, BagID: bagID, Status: db.StoredBagStatusActive})
	removeErr := errors.New("storage temporarily unavailable")
	stg := &cleanupStorageStub{
		Client:    storage.NewClient("", "./provider", nil, nil),
		path:      filepath.Join("provider", hex.EncodeToString(bagID)),
		removeErr: removeErr,
	}
	svc := &Service{db: xdb, storage: stg}
	reason := db.StoredBagStopReasonProviderRemoved

	if err := svc.stopBagContract(t.Context(), addr, bagID, nil, reason); !errors.Is(err, removeErr) {
		t.Fatalf("expected removal error, got %v", err)
	}
	bag, err := xdb.GetContract(addr)
	if err != nil {
		t.Fatal(err)
	}
	if bag.Status != db.StoredBagStatusActive {
		t.Fatalf("status after failed removal = %v, want active", bag.Status)
	}

	stg.removeErr = nil
	if err := svc.stopBagContract(t.Context(), addr, bagID, nil, reason); err != nil {
		t.Fatal(err)
	}
	bag, err = xdb.GetContract(addr)
	if err != nil {
		t.Fatal(err)
	}
	if stg.removeCalls != 2 || bag.Status != db.StoredBagStatusStopped {
		t.Fatalf("retry resulted in %d removal attempts and status %v", stg.removeCalls, bag.Status)
	}
}
