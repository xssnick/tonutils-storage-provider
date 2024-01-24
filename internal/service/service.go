package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
	"github.com/xssnick/tonutils-storage-provider/pkg/contract"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
	"math/big"
	"sync"
)

type StorageInfo struct {
	Status     string
	Downloaded uint64
	Proof      []byte
}

type DB interface {
	SetContract(bag db.StoredBag) error
	GetContract(addr string) (db.StoredBag, error)
	ListContracts() ([]db.StoredBag, error)
}

type Storage interface {
	GetBag(ctx context.Context, bagId []byte) (*storage.BagDetailed, error)
	GetPieceProof(ctx context.Context, bagId []byte, piece uint64) ([]byte, error)
	StartDownload(ctx context.Context, bagId []byte, downloadAll bool) error
	RemoveBag(ctx context.Context, bagId []byte, withFiles bool) error
}

type Service struct {
	ton     ton.APIClientWrapped
	storage Storage
	db      DB

	key            ed25519.PrivateKey
	wallet         *wallet.Wallet
	minRatePerMb   tlb.Coins
	minSpan        uint32
	maxSpan        uint32
	spaceAllocated uint64
	globalCtx      context.Context
	stop           func()

	warns map[string]string

	mx sync.RWMutex
}

func NewService(ton ton.APIClientWrapped, storage Storage, xdb DB, key ed25519.PrivateKey, w *wallet.Wallet, minRatePerMb tlb.Coins, spaceAllocated uint64, minSpan, maxSpan uint32) (*Service, error) {
	w.GetSpec().(*wallet.SpecV3).SetMessagesTTL(120)

	globalCtx, stop := context.WithCancel(context.Background())
	s := &Service{
		key:            key,
		ton:            ton,
		storage:        storage,
		db:             xdb,
		wallet:         w,
		minRatePerMb:   minRatePerMb,
		minSpan:        minSpan,
		maxSpan:        maxSpan,
		spaceAllocated: spaceAllocated,
		globalCtx:      globalCtx,
		stop:           stop,
		warns:          map[string]string{},
	}

	bags, err := s.db.ListContracts()
	if err != nil {
		return nil, fmt.Errorf("failed to get master block: %w", err)
	}

	for _, bag := range bags {
		if bag.Status != db.StoredBagStatusStopped {
			go s.bagWorker(address.MustParseAddr(bag.ContractAddr))
		}
	}

	return s, nil
}

var ErrUnsupportedContract = fmt.Errorf("unsupported contract")

func (s *Service) GetStorageInfo() (minSpan, maxSpan uint32, spaceAvailable uint64, ratePerMB tlb.Coins) {
	minSpan = s.minSpan
	maxSpan = s.maxSpan
	ratePerMB = s.minRatePerMb

	list, err := s.db.ListContracts()
	if err != nil {
		return
	}

	spaceAvailable = s.spaceAllocated
	for _, st := range list {
		if st.Status == db.StoredBagStatusActive {
			spaceAvailable -= st.Size
		}
	}
	return
}

var ErrNotDeployed = fmt.Errorf("contract is not deployed")
var ErrTooShortSpan = fmt.Errorf("too short proof time")
var ErrTooLongSpan = fmt.Errorf("too long proof time")
var ErrLowBalance = fmt.Errorf("contract available balance should be at least 0.08 TON")
var ErrLowBounty = fmt.Errorf("bounty should be at least 0.05 TON to cover fees")
var ErrTooLowRate = fmt.Errorf("too low rate per mb")
var ErrNoSpace = fmt.Errorf("not enough free space to store requested bag")

func (s *Service) FetchStorageInfo(ctx context.Context, contractAddr *address.Address, byteToProof uint64) (*StorageInfo, error) {
	if !contractAddr.IsBounceable() || contractAddr.IsTestnetOnly() || contractAddr.Workchain() != 0 {
		return nil, fmt.Errorf("incorrect address flags")
	}
	ctx = s.ton.Client().StickyContext(ctx)

	log.Info().Str("addr", contractAddr.String()).Msg("received request to host bag, checking...")

	bag, err := s.db.GetContract(contractAddr.String())
	if err == nil {
		if bag.Status != db.StoredBagStatusStopped {
			s.mx.Lock()
			defer s.mx.Unlock()

			// idempotency
			return s.fetchStorageInfo(ctx, bag, byteToProof, contractAddr.String())
		}
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return nil, fmt.Errorf("failed to read db: %w", err)
	}

	log.Info().Str("addr", contractAddr.String()).Msg("verifying...")

	master, err := s.ton.CurrentMasterchainInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get master block: %w", err)
	}

	acc, err := s.ton.WaitForBlock(master.SeqNo).GetAccount(ctx, master, contractAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get account: %w", err)
	}

	if !acc.IsActive {
		return nil, ErrNotDeployed
	}

	if !bytes.Equal(acc.Code.Hash(), contract.V1Code.Hash()) {
		return nil, ErrUnsupportedContract
	}

	si, err := contract.GetStorageInfoV1(ctx, s.ton, master, contractAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage info: %w", err)
	}

	pi, contractAvailableBalance, err := contract.GetProviderDataV1(ctx, s.ton, master, contractAddr, s.key.Public().(ed25519.PublicKey))
	if err != nil {
		if errors.Is(err, contract.ErrProviderNotFound) {
			return nil, fmt.Errorf("provider is not exists in this contract: %s", hex.EncodeToString(s.key.Public().(ed25519.PublicKey)))
		}
		return nil, fmt.Errorf("failed to run contract method get_provider_info: %w", err)
	}

	if pi.MaxSpan < s.minSpan {
		return nil, ErrTooShortSpan
	}
	if pi.MaxSpan > s.maxSpan {
		return nil, ErrTooLongSpan
	}

	if contractAvailableBalance.Nano().Cmp(tlb.MustFromTON("0.08").Nano()) < 0 {
		return nil, ErrLowBalance
	}

	mul := new(big.Int).Mul(pi.RatePerMB.Nano(), new(big.Int).SetUint64(si.Size))
	mul = mul.Mul(mul, big.NewInt(int64(pi.MaxSpan)))
	bounty := new(big.Int).Div(mul, big.NewInt(24*60*60*1024*1024))

	if tlb.MustFromTON("0.05").Nano().Cmp(bounty) > 0 {
		// all fees for proofing are at most 0.05 ton (in most cases), so if bounty is less we will spend more than earn
		return nil, ErrLowBounty
	}

	if pi.RatePerMB.Nano().Cmp(s.minRatePerMb.Nano()) < 0 {
		return nil, ErrTooLowRate
	}

	if s.spaceAllocated < si.Size {
		return nil, ErrNoSpace
	}

	list, err := s.db.ListContracts()
	if err != nil {
		return nil, fmt.Errorf("failed to get current contracts: %w", err)
	}

	left := s.spaceAllocated - si.Size
	for _, st := range list {
		if st.Status == db.StoredBagStatusActive {
			if left < st.Size {
				return nil, ErrNoSpace
			}
			left -= st.Size
		}
	}

	s.mx.Lock()
	defer s.mx.Unlock()

	bag, err = s.db.GetContract(contractAddr.String())
	if err == nil {
		if bag.Status != db.StoredBagStatusStopped {
			// idempotency
			return s.fetchStorageInfo(ctx, bag, byteToProof, contractAddr.String())
		}
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return nil, fmt.Errorf("failed to read db: %w", err)
	}

	if err = s.db.SetContract(db.StoredBag{
		ContractAddr: contractAddr.String(),
		Status:       db.StoredBagStatusAdded,
	}); err != nil {
		return nil, fmt.Errorf("failed to add to db: %w", err)
	}

	go s.bagWorker(contractAddr)
	return s.fetchStorageInfo(ctx, bag, byteToProof, contractAddr.String())
}

func (s *Service) fetchStorageInfo(ctx context.Context, bag db.StoredBag, byteToProof uint64, contract string) (*StorageInfo, error) {
	if len(bag.BagID) == 0 {
		return &StorageInfo{
			Status: "resolving",
		}, nil
	}

	b, err := s.storage.GetBag(ctx, bag.BagID)
	if err != nil {
		return nil, fmt.Errorf("failed to get bag from storage: %w", err)
	}

	var proof []byte
	status := "active"
	if b.Downloaded != b.Size || b.Size == 0 {
		status = "downloading"
		if b.Downloaded == 0 {
			status = "resolving"
		}
	} else {
		if w := s.warns[contract]; w != "" {
			status = "warning-" + w
		} else {
			if byteToProof >= b.BagSize {
				return nil, fmt.Errorf("byte is not exist in the given bag")
			}

			proof, err = s.storage.GetPieceProof(ctx, bag.BagID, byteToProof/uint64(b.PieceSize))
			if err != nil {
				return nil, fmt.Errorf("failed to get piece proof from storage: %w", err)
			}
		}
	}

	return &StorageInfo{
		Status:     status,
		Downloaded: b.Downloaded,
		Proof:      proof,
	}, nil
}
