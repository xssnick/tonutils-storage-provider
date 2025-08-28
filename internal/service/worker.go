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
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
	"github.com/xssnick/tonutils-storage-provider/pkg/contract"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
	"math/big"
	"strings"
	"time"
)

func (s *Service) bagWorker(contractAddr *address.Address, info *db.ContractInfo) {
	var torrentSize uint64
	var pieceSize uint32
	var torrentMerkle = make([]byte, 32)
	var ownerAddress *address.Address
	var bagId = make([]byte, 32)
	contractFetched, verified, downloaded := false, false, false

	startedAt := time.Now()

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

				usedByAnother := ""
				list, err := s.db.ListContracts()
				if err != nil {
					return fmt.Errorf("failed to list contracts from db: %w", err)
				}

				for _, st := range list {
					if st.Status == db.StoredBagStatusActive &&
						bytes.Equal(st.BagID, bagId) && st.ContractAddr != contractAddr.String() {
						usedByAnother = st.ContractAddr
						break
					}
				}

				if usedByAnother == "" {
					bd, err := s.storage.GetBag(ctx, bagId)
					if err != nil {
						if strings.HasSuffix(err.Error(), "not found") {
							log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bag already removed")
							return nil
						}
						return fmt.Errorf("failed to get bag from storage: %w", err)
					}

					if strings.HasSuffix(bd.Path, "/provider/"+hex.EncodeToString(bagId)) {
						// delete only what provider added
						if err := s.storage.RemoveBag(ctx, bagId, true); err != nil {
							return fmt.Errorf("failed to remove bag from storage: %w", err)
						}

						log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bag removed")
					} else {
						log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Str("path", bd.Path).Msg("bag is not removed, because was added not by provider")
					}
				} else {
					log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Str("another_contract", usedByAnother).Msg("bag is not removed, used by another contract")
				}

				if err := s.db.SetContract(db.StoredBag{
					BagID:        bagId,
					Size:         0,
					ContractAddr: contractAddr.String(),
					Status:       db.StoredBagStatusStopped,
				}); err != nil {
					return fmt.Errorf("failed to update contract in db: %w", err)
				}
				log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("storage for contract stopped")
				return nil
			}(); err != nil {
				log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to set stopped contract to db, will be retried")
				wait = 3 * time.Second

				continue
			}

			break
		}
	}

	log.Info().Str("addr", contractAddr.String()).Msg("bag hosting routine is started")

	var lastPercent float64
	var lastTxAt, lastDownloadPercentUpdateAt time.Time
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
					return fmt.Errorf("failed to load contract owner addr: %w", err)
				}

				torrentSize = size.Uint64()
				merkleHash.FillBytes(torrentMerkle)
				torrentHash.FillBytes(bagId)

				return nil
			}()
			if err != nil {
				log.Error().Err(err).Str("addr", contractAddr.String()).Msg("failed to fetch storage contract info, will be retried in 5s")
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

			if bag.InfoLoaded {
				if !verified {
					mh, err := hex.DecodeString(bag.MerkleHash)
					if err != nil {
						log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("merkle hash is not hex")
						wait = 5 * time.Second
						continue
					}

					addr, sx, _, err := contract.PrepareV1DeployData(bagId, mh, bag.BagSize, bag.PieceSize, ownerAddress, nil)
					if err != nil {
						log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to prepare contract deploy data, will be retried in 5s")
						wait = 5 * time.Second
						continue
					}

					if addr.String() != contractAddr.String() {
						log.Warn().Str("addr", contractAddr.String()).
							Hex("merkle", mh).
							Hex("code_hash", sx.Code.Hash()).
							Uint64("size", bag.BagSize).
							Uint32("piece", bag.PieceSize).
							Str("owner", ownerAddress.String()).
							Str("expected_addr", addr.String()).
							Hex("bag", bagId).
							Msg("contract is not genuine, dropping")

						drop()
						continue
					}

					if bag.Size > s.maxBagSize && bag.Downloaded != bag.Size {
						log.Warn().Str("addr", contractAddr.String()).
							Uint64("size", bag.BagSize).
							Uint32("piece", bag.PieceSize).
							Uint64("max_size", s.maxBagSize).
							Str("owner", ownerAddress.String()).
							Hex("bag", bagId).
							Msg("bag size is too big, dropping")

						drop()
						continue
					}

					log.Info().Str("addr", contractAddr.String()).
						Hex("merkle", mh).
						Hex("code_hash", sx.Code.Hash()).
						Uint64("size", bag.BagSize).
						Uint32("piece", bag.PieceSize).
						Str("owner", ownerAddress.String()).
						Hex("bag", bagId).
						Msg("contract is verified, starting worker")

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
						ContractInfo: info,
					}); err != nil {
						log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to set contract to db, will be retried in 5s")
						wait = 5 * time.Second
						continue
					}

					verified = true
					lastDownloadPercentUpdateAt = time.Now()
				}

				if bag.Downloaded != bag.Size {
					progress := (float64(bag.Downloaded) / float64(bag.Size)) * 100
					if progress > lastPercent {
						lastPercent = progress
						lastDownloadPercentUpdateAt = time.Now()
					}
					log.Debug().Str("addr", contractAddr.String()).Hex("bag", bagId).Str("progress", fmt.Sprintf("%.2f", progress)).Msg("download is still in progress, will wait and check again")

					if lastDownloadPercentUpdateAt.Before(time.Now().Add(-time.Duration(s.maxMinutesNoProgress) * time.Minute)) {
						log.Warn().Str("addr", contractAddr.String()).
							Uint64("size", bag.BagSize).
							Uint32("piece", bag.PieceSize).
							Str("owner", ownerAddress.String()).
							Hex("bag", bagId).
							Msg("no download progress for too long, dropping")

						drop()
						continue
					}

					wait = 5 * time.Second
					continue
				}

				log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("bag is downloaded")

				downloaded = true
			} else {
				log.Info().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("info is not downloaded yet, will wait and check again")
			}
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

			pi, contractAvailableBalance, err := contract.GetProviderDataV1(ctx, s.ton, master, contractAddr, s.key.Public().(ed25519.PublicKey))
			if err != nil {
				if errors.Is(err, contract.ErrProviderNotFound) {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("provider was removed by the owner, dropping storage")

					drop()
					return nil
				}
				return fmt.Errorf("failed to get provider info: %w", err)
			}

			if info == nil || (pi.MaxSpan != info.MaxSpan || pi.RatePerMB.Nano().String() != info.PerMB) {
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

				if pi.RatePerMB.Nano().Cmp(s.minRatePerMb.Nano()) < 0 {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("too low rate per mb in contract, declining storage")

					drop()
					return nil
				}

				info = &db.ContractInfo{
					MaxSpan: pi.MaxSpan,
					PerMB:   pi.RatePerMB.Nano().String(),
				}

				if err = s.db.SetContract(db.StoredBag{
					BagID:        bagId,
					Size:         torrentSize,
					ContractAddr: contractAddr.String(),
					Status:       db.StoredBagStatusActive,
					ContractInfo: info,
				}); err != nil {
					log.Error().Err(err).Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("failed to update contract to db, will be retried in 5s")
				}
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

			if contractAvailableBalance.Nano().Cmp(bounty) < 0 {
				var deadline int64
				fresh := pi.LastProofAt.Unix() <= 0
				if fresh {
					deadline = startedAt.Unix() + 3600
				} else {
					deadline = pi.LastProofAt.Unix() + int64(pi.MaxSpan) + 3600
				}

				log.Debug().Str("bag_balance", contractAvailableBalance.String()).
					Str("bounty", tlb.FromNanoTON(bounty).String()).
					Uint64("byte", pi.ByteToProof).Hex("bag", bagId).
					Int64("sec_till_drop", deadline-time.Now().Unix()).Hex("bag", bagId).
					Str("addr", contractAddr.String()).Msg("not enough contract balance for our bounty")

				if deadline < time.Now().Unix() {
					log.Warn().Str("addr", contractAddr.String()).Hex("bag", bagId).Msg("not enough balance for too long, removing torrent")

					drop()
				}
				wait = 30 * time.Second
				s.mx.Lock()
				s.warns[contractAddr.String()] = "balance"
				s.mx.Unlock()
				return nil
			}

			s.mx.Lock()
			delete(s.warns, contractAddr.String())
			s.mx.Unlock()

			if wBalance.Nano().Cmp(tlb.MustFromTON("0.08").Nano()) < 0 {
				return fmt.Errorf("too low wallet balance: %s", wBalance.String())
			}

			if downloaded {
				if int64(block.BlockInfo.GenUtime) >= pi.LastProofAt.Unix()+int64(pi.MaxSpan) &&
					lastTxAt.Add(120*time.Second).Before(time.Unix(int64(block.BlockInfo.GenUtime), 0)) {

					proofData, err := s.storage.GetPieceProof(ctx, bagId, pi.ByteToProof/uint64(pieceSize))
					if err != nil {
						return fmt.Errorf("failed to get proof: %w", err)
					}

					proof, err := cell.FromBOC(proofData)
					if err != nil {
						return fmt.Errorf("failed to parse proof: %w", err)
					}

					toSign := cell.BeginCell().MustStoreUInt(pi.Nonce, 64).MustStoreRef(proof)

					payload := cell.BeginCell().
						MustStoreUInt(0x48f548ce, 32).
						MustStoreUInt(0, 64).
						MustStoreSlice(s.key.Public().(ed25519.PublicKey), 256).
						MustStoreSlice(toSign.EndCell().Sign(s.key), 512).
						MustStoreBuilder(toSign).
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
					log.Debug().Str("wallet_balance", wBalance.String()).Str("bounty_before_fee", tlb.FromNanoTON(bounty).String()).Int64("sec_till_proof", (pi.LastProofAt.Unix()+int64(pi.MaxSpan))-int64(block.BlockInfo.GenUtime)).Uint64("byte", pi.ByteToProof).Hex("bag", bagId).Str("addr", contractAddr.String()).Msg("too early to proof, waiting...")
				}

				// wait till proof or 6 sec (max of this two)
				tillProof := time.Duration((pi.LastProofAt.Unix()+int64(pi.MaxSpan))-time.Now().Unix()) * time.Second
				wait = max(tillProof, 6*time.Second)
			} else {
				wait = 15 * time.Second
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
