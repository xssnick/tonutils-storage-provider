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
	RemoveBag(ctx context.Context, bagId []byte) error
}

type Service struct {
	ton     ton.APIClientWrapped
	storage Storage
	db      DB

	withdrawAddress *address.Address
	withdrawAmount  tlb.Coins
	minRatePerMb    tlb.Coins
	minSpan         uint32
	maxSpan         uint32
	spaceAllocated  uint64
	key             ed25519.PrivateKey
	globalCtx       context.Context
	stop            func()

	mx sync.RWMutex
}

func NewService(ton ton.APIClientWrapped, storage Storage, xdb DB, key ed25519.PrivateKey, withdrawalAddress *address.Address, minWithdrawAmount, minRatePerMb tlb.Coins, spaceAllocated uint64, minSpan, maxSpan uint32) (*Service, error) {
	globalCtx, stop := context.WithCancel(context.Background())
	s := &Service{
		ton:             ton,
		storage:         storage,
		db:              xdb,
		withdrawAddress: withdrawalAddress,
		withdrawAmount:  minWithdrawAmount,
		minRatePerMb:    minRatePerMb,
		minSpan:         minSpan,
		maxSpan:         maxSpan,
		spaceAllocated:  spaceAllocated,
		key:             key,
		globalCtx:       globalCtx,
		stop:            stop,
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

func (s *Service) GetStorageInfo() (pub ed25519.PublicKey, withdrawAddress *address.Address, minSpan, maxSpan uint32, spaceAvailable uint64, ratePerMB tlb.Coins) {
	pub = s.key.Public().(ed25519.PublicKey)
	withdrawAddress = s.withdrawAddress
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

func (s *Service) AddBag(ctx context.Context, contractAddr *address.Address, size uint64) error {
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

	pub := s.key.Public().(ed25519.PublicKey)
	res, err := s.ton.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_provider_info", new(big.Int).SetBytes(pub))
	if err != nil {
		lgErr, ok := err.(ton.ContractExecError)
		if ok && lgErr.Code == 404 {
			return fmt.Errorf("provider is not exists in this contract")
		}
		return fmt.Errorf("failed to run contract method get_provider_info: %w", err)
	}

	span, err := res.Int(4)
	if err != nil {
		return fmt.Errorf("failed to read get_provider_info span returned value: %w", err)
	}

	ratePerMB, err := res.Int(5)
	if err != nil {
		return fmt.Errorf("failed to read get_provider_info rate returned value: %w", err)
	}

	providerAddrSlice, err := res.Slice(6)
	if err != nil {
		return fmt.Errorf("failed to read get_provider_info addr returned value: %w", err)
	}
	providerAddr, err := providerAddrSlice.LoadAddr()
	if err != nil {
		return fmt.Errorf("failed to parse provider addr returned value: %w", err)
	}

	contractAvailableBalance, err := res.Int(7)
	if err != nil {
		return fmt.Errorf("failed to read get_provider_info contract available balance returned value: %w", err)
	}

	if uint32(span.Uint64()) < s.minSpan {
		return fmt.Errorf("too short span")
	}
	if uint32(span.Uint64()) > s.maxSpan {
		return fmt.Errorf("too long span")
	}

	if contractAvailableBalance.Cmp(tlb.MustFromTON("0.1").Nano()) < 0 {
		return fmt.Errorf("contarct available balance should be at least 0.1 TON")
	}

	if providerAddr.String() != s.withdrawAddress.String() {
		return fmt.Errorf("reward address not match")
	}

	if ratePerMB.Cmp(s.minRatePerMb.Nano()) < 0 {
		return fmt.Errorf("too low rate per mb")
	}

	if s.spaceAllocated < size {
		return fmt.Errorf("not enough free space to store requested bag")
	}

	list, err := s.db.ListContracts()
	if err != nil {
		return fmt.Errorf("failed to get current contracts: %w", err)
	}

	left := s.spaceAllocated - size
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

				master, err := s.ton.GetMasterchainInfo(ctx)
				if err != nil {
					return fmt.Errorf("failed to get master block: %w", err)
				}

				pub := s.key.Public().(ed25519.PublicKey)
				res, err := s.ton.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_provider_info", new(big.Int).SetBytes(pub))
				if err != nil {
					lgErr, ok := err.(ton.ContractExecError)
					if !ok || (lgErr.Code != -256 && lgErr.Code != 404) {
						return fmt.Errorf("failed to run contract method get_provider_info: %w", err)
					}
					// if it is 404 or -256 then contract or provider is not exist, skip withdrawal
				} else {
					lastCorrectProofAt, err := res.Int(1)
					if err != nil {
						return fmt.Errorf("failed to read get_provider_info balance returned value: %w", err)
					}

					if err := s.withdrawFromContract(s.globalCtx, contractAddr, bagId, lastCorrectProofAt); err != nil {
						return fmt.Errorf("failed to to withdraw balance from contrcat: %w", err)
					}
				}

				usedByAnother := false
				list, err := s.db.ListContracts()
				for _, st := range list {
					if st.Status == db.StoredBagStatusActive &&
						bytes.Equal(st.BagID, bagId) && st.ContractAddr != contractAddr.String() {
						usedByAnother = true
						break
					}
				}

				if !usedByAnother {
					if err := s.storage.RemoveBag(ctx, bagId); err != nil {
						return fmt.Errorf("failed to remove bag from storage: %w", err)
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
			ctx, cancel := context.WithTimeout(s.globalCtx, 30*time.Second)
			defer cancel()

			master, err := s.ton.GetMasterchainInfo(ctx)
			if err != nil {
				return fmt.Errorf("failed to get master block: %w", err)
			}

			block, err := s.ton.WaitForBlock(master.SeqNo).GetBlockData(ctx, master)
			if err != nil {
				return fmt.Errorf("failed to get master block data: %w", err)
			}

			pub := s.key.Public().(ed25519.PublicKey)
			res, err := s.ton.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_provider_info", new(big.Int).SetBytes(pub))
			if err != nil {
				return fmt.Errorf("failed to run contract method get_provider_info: %w", err)
			}

			balance, err := res.Int(0)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info balance returned value: %w", err)
			}

			lastCorrectProofAt, err := res.Int(1)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info balance returned value: %w", err)
			}

			lastProofAt, err := res.Int(2)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info last proof time returned value: %w", err)
			}

			byteToProof, err := res.Int(3)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info byte to proof returned value: %w", err)
			}

			span, err := res.Int(4)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info span returned value: %w", err)
			}

			ratePerMB, err := res.Int(5)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info rate returned value: %w", err)
			}

			providerAddrSlice, err := res.Slice(6)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info addr returned value: %w", err)
			}
			providerAddr, err := providerAddrSlice.LoadAddr()
			if err != nil {
				return fmt.Errorf("failed to parse provider addr returned value: %w", err)
			}

			contractAvailableBalance, err := res.Int(7)
			if err != nil {
				return fmt.Errorf("failed to read get_provider_info contract available balance returned value: %w", err)
			}

			if providerAddr.String() != s.withdrawAddress.String() {
				log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("withdrawal address is incorrect, dropping storage")

				drop()
				return nil
			}

			if ratePerMB.Cmp(s.minRatePerMb.Nano()) < 0 {
				log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("too low rate per mb in contract, declining storage")

				drop()
				return nil
			}

			if balance.Cmp(s.withdrawAmount.Nano()) >= 0 {
				if err = s.withdrawFromContract(ctx, contractAddr, bagId, lastCorrectProofAt); err != nil {
					return fmt.Errorf("failed to withdraw: %w", err)
				}
			}

			mul := new(big.Int).Mul(ratePerMB, new(big.Int).SetUint64(torrentSize))
			mul = mul.Mul(mul, span)
			bounty := new(big.Int).Div(mul, big.NewInt(24*60*60*1024*1024))

			// we want contract to have enough balance for fee and bounty
			bountyFee := new(big.Int).Add(bounty, tlb.MustFromTON("0.025").Nano())
			if contractAvailableBalance.Cmp(bountyFee) == -1 {
				deadline := lastProofAt.Int64() + 86400 + 43200

				log.Info().Str("bag_balance", tlb.FromNanoTON(contractAvailableBalance).String()).
					Str("balance", tlb.FromNanoTON(balance.Add(balance, bounty)).String()).
					Uint64("byte", byteToProof.Uint64()).Hex("bag", bagId).
					Int64("sec_till_drop", deadline-time.Now().Unix()).Hex("bag", bagId).
					Str("addr", contractAddr.String()).Msg("not enough contract balance for our bounty")

				if deadline < time.Now().Unix() {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("not enough balance for too long, removing torrent")

					drop()
				}
				wait = 5 * time.Minute
				return nil
			}

			if downloaded && int64(block.BlockInfo.GenUtime) > lastProofAt.Int64()+span.Int64() {
				proofData, err := s.storage.GetPieceProof(ctx, bagId, byteToProof.Uint64()/uint64(pieceSize))
				if err != nil {
					return fmt.Errorf("failed to get proof: %w", err)
				}

				proof, err := cell.FromBOC(proofData)
				if err != nil {
					return fmt.Errorf("failed to parse proof: %w", err)
				}

				payload := cell.BeginCell().
					MustStoreSlice(bagId, 256).
					MustStoreUInt(2, 8).
					MustStoreBigUInt(byteToProof, 64).
					MustStoreRef(proof).
					EndCell()

				// wait for next block, because it looks like LS sometimes uses prev block to emulate externals
				if err = s.ton.WaitForBlock(master.SeqNo+1).SendExternalMessage(ctx, &tlb.ExternalMessage{
					DstAddr: contractAddr,
					Body: cell.BeginCell().
						MustStoreUInt(0x419d5d4d, 32).
						MustStoreUInt(0, 64).
						MustStoreSlice(pub, 256).
						MustStoreSlice(payload.Sign(s.key), 512).
						MustStoreRef(payload).
						EndCell(),
				}); err != nil {
					if strings.Contains(err.Error(), " terminating vm with exit code 430") {
						// too early for this ls, will retry
						wait = 3 * time.Second
						return nil
					}
					return fmt.Errorf("failed to send piece proof: %w", err)
				}
				log.Info().Str("bag_balance", tlb.FromNanoTON(contractAvailableBalance).String()).Str("balance", tlb.FromNanoTON(balance.Add(balance, bounty)).String()).Uint64("byte", byteToProof.Uint64()).Hex("bag", bagId).Str("addr", contractAddr.String()).Msg("proof message sent to storage contract")

				// we need to wait for potential commit not send external message too many times
				wait = 15 * time.Second
				return nil
			} else {
				log.Info().Str("balance", tlb.FromNanoTON(balance).String()).Int64("sec_till_proof", (lastProofAt.Int64()+span.Int64())-int64(block.BlockInfo.GenUtime)).Uint64("byte", byteToProof.Uint64()).Hex("bag", bagId).Str("addr", contractAddr.String()).Msg("too early to proof, waiting...")
			}

			wait = 1 * time.Minute

			// wait till proof or 5 min (min of this two)
			tillProof := time.Duration((lastProofAt.Int64()+span.Int64())-time.Now().Unix()) * time.Second
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

func (s *Service) withdrawFromContract(ctx context.Context, contractAddr *address.Address, bagId []byte, lastCorrectProofAt *big.Int) error {
	payload := cell.BeginCell().
		MustStoreSlice(bagId, 256).
		MustStoreUInt(1, 8).
		MustStoreBigUInt(lastCorrectProofAt, 32).
		MustStoreAddr(s.withdrawAddress).
		EndCell()

	pub := s.key.Public().(ed25519.PublicKey)
	if err := s.ton.SendExternalMessage(ctx, &tlb.ExternalMessage{
		DstAddr: contractAddr,
		Body: cell.BeginCell().
			MustStoreUInt(0x46ed2e94, 32).
			MustStoreUInt(0, 64).
			MustStoreSlice(pub, 256).
			MustStoreSlice(payload.Sign(s.key), 512).
			MustStoreRef(payload).
			EndCell(),
	}); err != nil {
		if strings.Contains(err.Error(), " terminating vm with exit code 405") {
			log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("no balance available to withdraw")
			return nil
		}
		return fmt.Errorf("failed to send withdraw request: %w", err)
	}
	log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("withdraw request sent to storage contract")
	return nil
}
