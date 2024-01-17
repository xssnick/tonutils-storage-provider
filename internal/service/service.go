package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
	"github.com/xssnick/tonutils-storage-provider/pkg/contract"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
	"math/big"
	"strings"
	"sync"
	"time"
)

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

	wallet         *wallet.Wallet
	minRatePerMb   tlb.Coins
	minSpan        uint32
	maxSpan        uint32
	spaceAllocated uint64
	globalCtx      context.Context
	stop           func()

	mx sync.RWMutex
}

func NewService(ton ton.APIClientWrapped, storage Storage, xdb DB, w *wallet.Wallet, minRatePerMb tlb.Coins, spaceAllocated uint64, minSpan, maxSpan uint32) (*Service, error) {
	w.GetSpec().(*wallet.SpecV3).SetMessagesTTL(120)

	globalCtx, stop := context.WithCancel(context.Background())
	s := &Service{
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

func (s *Service) GetStorageInfo() (withdrawAddress *address.Address, minSpan, maxSpan uint32, spaceAvailable uint64, ratePerMB tlb.Coins) {
	withdrawAddress = s.wallet.WalletAddress()
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

func (s *Service) AddBag(ctx context.Context, contractAddr *address.Address) error {
	if !contractAddr.IsBounceable() || contractAddr.IsTestnetOnly() {
		return fmt.Errorf("incorrect address flags")
	}
	ctx = s.ton.Client().StickyContext(ctx)

	master, err := s.ton.CurrentMasterchainInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get master block: %w", err)
	}

	log.Info().Str("addr", contractAddr.String()).Msg("received request to host bag, checking...")

	bag, err := s.db.GetContract(contractAddr.String())
	if err == nil {
		if bag.Status != db.StoredBagStatusStopped {
			// idempotency
			return nil
		}
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return fmt.Errorf("failed to read db: %w", err)
	}

	log.Info().Str("addr", contractAddr.String()).Msg("verifying...")

	acc, err := s.ton.WaitForBlock(master.SeqNo).GetAccount(ctx, master, contractAddr)
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}

	if !acc.IsActive {
		return fmt.Errorf("contract is not deployed")
	}

	if !bytes.Equal(acc.Code.Hash(), contract.V1Code.Hash()) {
		return ErrUnsupportedContract
	}

	si, err := contract.GetStorageInfoV1(ctx, s.ton, master, contractAddr)
	if err != nil {
		return fmt.Errorf("failed to get storage info: %w", err)
	}

	pi, contractAvailableBalance, err := contract.GetProviderDataV1(ctx, s.ton, master, contractAddr, s.wallet.WalletAddress().Data())
	if err != nil {
		if errors.Is(err, contract.ErrProviderNotFound) {
			return fmt.Errorf("provider is not exists in this contract: %s", hex.EncodeToString(s.wallet.WalletAddress().Data()))
		}
		return fmt.Errorf("failed to run contract method get_provider_info: %w", err)
	}

	if pi.MaxSpan < s.minSpan {
		return fmt.Errorf("too short span")
	}
	if pi.MaxSpan > s.maxSpan {
		return fmt.Errorf("too long span")
	}

	if contractAvailableBalance.Nano().Cmp(tlb.MustFromTON("0.2").Nano()) < 0 {
		return fmt.Errorf("contarct available balance should be at least 0.2 TON")
	}

	mul := new(big.Int).Mul(pi.RatePerMB.Nano(), new(big.Int).SetUint64(si.Size))
	mul = mul.Mul(mul, big.NewInt(int64(pi.MaxSpan)))
	bounty := new(big.Int).Div(mul, big.NewInt(24*60*60*1024*1024))

	if tlb.MustFromTON("0.05").Nano().Cmp(bounty) > 0 {
		// all fees for proofing are at most 0.05 ton (in most cases), so if bounty is less we will spend more than earn
		return fmt.Errorf("bounty should be at least 0.05 TON to cover fees, it is %s", tlb.FromNanoTON(bounty).String()+" TON")
	}

	if pi.ProviderAddr.String() != s.wallet.WalletAddress().Bounce(true).String() {
		return fmt.Errorf("reward address not match")
	}

	if pi.RatePerMB.Nano().Cmp(s.minRatePerMb.Nano()) < 0 {
		return fmt.Errorf("too low rate per mb")
	}

	if s.spaceAllocated < si.Size {
		return fmt.Errorf("not enough free space to store requested bag")
	}

	list, err := s.db.ListContracts()
	if err != nil {
		return fmt.Errorf("failed to get current contracts: %w", err)
	}

	left := s.spaceAllocated - si.Size
	for _, st := range list {
		if st.Status == db.StoredBagStatusActive {
			if left < st.Size {
				return fmt.Errorf("not enough free space to store requested bag")
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
			return nil
		}
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return fmt.Errorf("failed to read db: %w", err)
	}

	if err = s.db.SetContract(db.StoredBag{
		ContractAddr: contractAddr.String(),
		Status:       db.StoredBagStatusAdded,
	}); err != nil {
		return fmt.Errorf("failed to add to db: %w", err)
	}

	go s.bagWorker(contractAddr)
	return nil
}

func (s *Service) bagWorker(contractAddr *address.Address) {
	var torrentSize uint64
	var pieceSize uint32
	var torrentMerkle = make([]byte, 32)
	var ownerAddress *address.Address
	var bagId = make([]byte, 32)
	contractFetched, verified, downloaded := false, false, false

	stopCtx, stop := context.WithCancel(s.globalCtx)
	defer stop()

	drop := func() {
		stop()

		wait := time.Duration(0)
		for {
			select {
			case <-s.globalCtx.Done():
				// want to exit
				return
			case <-time.After(wait):
			}

			if err := func() error {
				ctx, cancel := context.WithTimeout(s.globalCtx, 15*time.Second)
				defer cancel()

				usedByAnother := false
				list, err := s.db.ListContracts()
				if err != nil {
					return fmt.Errorf("failed to list contracts from db: %w", err)
				}

				for _, st := range list {
					if st.Status == db.StoredBagStatusActive &&
						bytes.Equal(st.BagID, bagId) && st.ContractAddr != contractAddr.String() {
						usedByAnother = true
						break
					}
				}

				if !usedByAnother {
					bd, err := s.storage.GetBag(ctx, bagId)
					if err != nil {
						return fmt.Errorf("failed to get bag from storage: %w", err)
					}

					if strings.HasSuffix(bd.Path, "/provider") {
						// delete only what was added by provider
						if err := s.storage.RemoveBag(ctx, bagId, false); err != nil {
							return fmt.Errorf("failed to remove bag from storage: %w", err)
						}
					}
				}

				if err := s.db.SetContract(db.StoredBag{
					BagID:        bagId,
					Size:         0,
					ContractAddr: contractAddr.String(),
					Status:       db.StoredBagStatusStopped,
				}); err != nil {
					return fmt.Errorf("failed to update contract in db: %w", err)
				}
				return nil
			}(); err != nil {
				log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to set stopped contract to db, will be retried")
				wait = 3 * time.Second

				continue
			}

			log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bag removed")
			break
		}
	}

	log.Info().Str("addr", contractAddr.String()).Msg("bag hosting routine is started")

	var lastTxAt time.Time
	var wait time.Duration
	for {
		select {
		case <-stopCtx.Done():
			return
		case <-time.After(wait):
		}

		if !contractFetched {
			err := func() error {
				ctx, cancel := context.WithTimeout(s.globalCtx, 30*time.Second)
				defer cancel()

				master, err := s.ton.CurrentMasterchainInfo(ctx)
				if err != nil {
					return fmt.Errorf("failed to get master block: %w", err)
				}

				res, err := s.ton.RunGetMethod(ctx, master, contractAddr, "get_storage_info")
				if err != nil {
					return fmt.Errorf("failed to run contract method get_storage_info: %w", err)
				}

				torrentHash, err := res.Int(0)
				if err != nil {
					return fmt.Errorf("failed to read get_storage_info hash returned value: %w", err)
				}

				size, err := res.Int(1)
				if err != nil {
					return fmt.Errorf("failed to read get_storage_info size returned value: %w", err)
				}

				_, err = res.Int(2)
				if err != nil {
					return fmt.Errorf("failed to read get_storage_info chunk size returned value: %w", err)
				}

				ownerAddr, err := res.Slice(3)
				if err != nil {
					return fmt.Errorf("failed to read get_storage_info owner address returned value: %w", err)
				}

				merkleHash, err := res.Int(4)
				if err != nil {
					return fmt.Errorf("failed to read get_provider_info merkle hash returned value: %w", err)
				}

				ownerAddress, err = ownerAddr.LoadAddr()
				if err != nil {
					return fmt.Errorf("failed to load contarct owner addr: %w", err)
				}

				torrentSize = size.Uint64()
				merkleHash.FillBytes(torrentMerkle)
				torrentHash.FillBytes(bagId)

				return nil
			}()
			if err != nil {
				log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to fetch storage contract info, will be retried in 5s")
				wait = 5 * time.Second
				continue
			}

			contractFetched = true
		}

		if !downloaded {
			bag, err := s.storage.GetBag(stopCtx, bagId)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				log.Warn().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to get bag, will be retried in 5s")
				wait = 5 * time.Second
				continue
			}

			if bag == nil {
				if err := s.storage.StartDownload(stopCtx, bagId, false); err != nil {
					log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to start header download, will be retried in 5s")
					wait = 5 * time.Second
					continue
				}

				bag, err = s.storage.GetBag(stopCtx, bagId)
				if err != nil {
					log.Warn().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to get bag, will be retried in 5s")
					wait = 5 * time.Second
					continue
				}
			}

			if !bag.InfoLoaded {
				log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("info is not downloaded yet, will wait and check again")
				wait = 5 * time.Second
				continue
			}

			if !verified {
				mh, err := hex.DecodeString(bag.MerkleHash)
				if err != nil {
					log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("merkle hash is not hex")
					wait = 5 * time.Second
					continue
				}

				addr, _, _, err := contract.PrepareV1DeployData(bagId, mh, bag.BagSize, bag.PieceSize, ownerAddress, nil)
				if err != nil {
					log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to prepare contract deploy data, will be retried in 5s")
					wait = 5 * time.Second
					continue
				}

				if addr.String() != contractAddr.String() {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("contract is not genuine, dropping")

					drop()
					continue
				}

				if err := s.storage.StartDownload(stopCtx, bagId, true); err != nil {
					log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to start full download, will be retried in 5s")
					wait = 5 * time.Second
					continue
				}

				log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bag is verified, downloading")

				pieceSize = bag.PieceSize
				if err = s.db.SetContract(db.StoredBag{
					BagID:        bagId,
					Size:         bag.BagSize,
					ContractAddr: contractAddr.String(),
					Status:       db.StoredBagStatusActive,
				}); err != nil {
					log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to set contract to db, will be retried in 5s")
					wait = 5 * time.Second
					continue
				}

				verified = true
			}

			if bag.Downloaded != bag.Size {
				progress := (float64(bag.Downloaded) / float64(bag.Size)) * 100
				log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Str("progress", fmt.Sprintf("%.2f", progress)).Msg("download is still in progress, will wait and check again")
				wait = 5 * time.Second
				continue
			}

			log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bag is downloaded")

			downloaded = true
		}

		err := func() error {
			ctx, cancel := context.WithTimeout(s.globalCtx, 180*time.Second)
			defer cancel()

			master, err := s.ton.GetMasterchainInfo(ctx)
			if err != nil {
				return fmt.Errorf("failed to get master block: %w", err)
			}

			block, err := s.ton.WaitForBlock(master.SeqNo).GetBlockData(ctx, master)
			if err != nil {
				return fmt.Errorf("failed to get master block data: %w", err)
			}

			wBalance, err := s.wallet.GetBalance(ctx, master)
			if err != nil {
				return fmt.Errorf("failed to get wallet balance: %w", err)
			}

			pi, contractAvailableBalance, err := contract.GetProviderDataV1(ctx, s.ton, master, contractAddr, s.wallet.WalletAddress().Data())
			if err != nil {
				if errors.Is(err, contract.ErrProviderNotFound) {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("provider was removed by the owner, dropping storage")

					drop()
					return nil
				}
				return fmt.Errorf("failed to get provider info: %w", err)
			}

			if pi.MaxSpan < s.minSpan {
				log.Warn().Str("addr", contractAddr.String()).Uint32("span", pi.MaxSpan).Hex("bag", bagId).Msg("too short span, dropping storage")

				drop()
				return nil
			}
			if pi.MaxSpan > s.maxSpan {
				log.Warn().Str("addr", contractAddr.String()).Uint32("span", pi.MaxSpan).Hex("bag", bagId).Msg("too short long, dropping storage")

				drop()
				return nil
			}

			if pi.ProviderAddr.String() != s.wallet.WalletAddress().Bounce(true).String() {
				log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("withdrawal address is incorrect, dropping storage")

				drop()
				return nil
			}

			if pi.RatePerMB.Nano().Cmp(s.minRatePerMb.Nano()) < 0 {
				log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("too low rate per mb in contract, declining storage")

				drop()
				return nil
			}

			mul := new(big.Int).Mul(pi.RatePerMB.Nano(), new(big.Int).SetUint64(torrentSize))
			mul = mul.Mul(mul, new(big.Int).SetUint64(uint64(pi.MaxSpan)))
			bounty := new(big.Int).Div(mul, big.NewInt(24*60*60*1024*1024))

			if tlb.MustFromTON("0.05").Nano().Cmp(bounty) > 0 {
				// all fees for proofing are 0.05 ton (in most cases), so if bounty is less we will spend more than earn
				log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bounty is less than fee, removing torrent")

				drop()
				return nil
			}

			if contractAvailableBalance.Nano().Cmp(bounty) == -1 {
				deadline := pi.LastProofAt.Unix() + 86400 + 43200

				log.Info().Str("bag_balance", contractAvailableBalance.String()).
					Str("bounty", tlb.FromNanoTON(bounty).String()).
					Uint64("byte", pi.ByteToProof).Hex("bag", bagId).
					Int64("sec_till_drop", deadline-time.Now().Unix()).Hex("bag", bagId).
					Str("addr", contractAddr.String()).Msg("not enough contract balance for our bounty")

				if deadline < time.Now().Unix() {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("not enough balance for too long, removing torrent")

					drop()
				}
				wait = 5 * time.Minute
				return nil
			}

			if wBalance.Nano().Cmp(tlb.MustFromTON("0.08").Nano()) < 0 {
				return fmt.Errorf("too low wallet balance: %s", wBalance.String())
			}

			if downloaded && int64(block.BlockInfo.GenUtime) >= pi.LastProofAt.Unix()+int64(pi.MaxSpan) &&
				lastTxAt.Add(120*time.Second).Before(time.Unix(int64(block.BlockInfo.GenUtime), 0)) {

				proofData, err := s.storage.GetPieceProof(ctx, bagId, pi.ByteToProof/uint64(pieceSize))
				if err != nil {
					return fmt.Errorf("failed to get proof: %w", err)
				}

				proof, err := cell.FromBOC(proofData)
				if err != nil {
					return fmt.Errorf("failed to parse proof: %w", err)
				}

				payload := cell.BeginCell().
					MustStoreUInt(0x419d5d4d, 32).
					MustStoreUInt(0, 64).
					MustStoreRef(proof).
					EndCell()

				// ttl protection to not resend tx twice
				lastTxAt = time.Now()

				log.Info().Str("bounty_before_fee", tlb.FromNanoTON(bounty).String()).Str("wallet_balance", wBalance.String()).Str("bag_balance", contractAvailableBalance.String()).Uint64("byte", pi.ByteToProof).Hex("bag", bagId).Str("addr", contractAddr.String()).Msg("sending proof to storage contract...")

				tx, _, err := s.wallet.SendWaitTransaction(ctx, wallet.SimpleMessage(contractAddr, tlb.MustFromTON("0.05"), payload))
				if err != nil {
					return fmt.Errorf("failed to send piece proof: %w", err)
				}

				log.Info().Hex("tx_hash", tx.Hash).Str("wallet_balance", wBalance.String()).Str("bounty_before_fee", tlb.FromNanoTON(bounty).String()).Uint64("byte", pi.ByteToProof).Hex("bag", bagId).Str("addr", contractAddr.String()).Msg("proof transaction sent to storage contract")

				return nil
			} else {
				log.Info().Str("wallet_balance", wBalance.String()).Str("bounty_before_fee", tlb.FromNanoTON(bounty).String()).Int64("sec_till_proof", (pi.LastProofAt.Unix()+int64(pi.MaxSpan))-int64(block.BlockInfo.GenUtime)).Uint64("byte", pi.ByteToProof).Hex("bag", bagId).Str("addr", contractAddr.String()).Msg("too early to proof, waiting...")
			}

			wait = 1 * time.Minute

			// wait till proof or 5 min (min of this two)
			tillProof := time.Duration((pi.LastProofAt.Unix()+int64(pi.MaxSpan))-time.Now().Unix()) * time.Second
			if tillProof <= 3*time.Second {
				wait = 3 * time.Second
			} else if tillProof < wait {
				wait = tillProof
			}

			return nil
		}()
		if err != nil {
			log.Warn().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to check storage contract state, will be retried in 5s")
			wait = 5 * time.Second
			continue
		}
	}
}
