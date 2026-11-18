package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
)

const (
	stoppedReconcileInterval       = 15 * time.Minute
	stoppedReconcileFetchTimeout   = 30 * time.Second
	stoppedReconcileRequestSpacing = time.Second
)

var errInvalidStoredContractAddress = errors.New("invalid stored contract address")

func (s *Service) startStoppedReconciler() {
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()

		for {
			select {
			case <-s.globalCtx.Done():
				return
			case <-timer.C:
			}

			if err := s.reconcileStoppedContracts(
				s.globalCtx,
				s,
				stoppedReconcileRequestSpacing,
			); err != nil && !errors.Is(err, context.Canceled) {
				log.Warn().Err(err).Msg("failed to reconcile stopped storage contracts")
			}

			timer.Reset(stoppedReconcileInterval)
		}
	}()
}

func (s *Service) reconcileStoppedContracts(
	ctx context.Context,
	fetcher storageInfoFetcher,
	requestSpacing time.Duration,
) error {
	bags, err := s.db.ListContracts()
	if err != nil {
		return fmt.Errorf("failed to list stopped contracts: %w", err)
	}

	attempted := false
	for _, bag := range bags {
		if bag.Status != db.StoredBagStatusStopped ||
			!stoppedReasonRetryable(bag.StopReason) {
			continue
		}

		if attempted && requestSpacing > 0 {
			timer := time.NewTimer(requestSpacing)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		attempted = true

		if err := ctx.Err(); err != nil {
			return err
		}

		contractAddr, err := address.ParseAddr(bag.ContractAddr)
		if err != nil {
			err = fmt.Errorf("%w: %v", errInvalidStoredContractAddress, err)
			if recordErr := s.recordStoppedReconcileFailure(bag.ContractAddr, err); recordErr != nil {
				return recordErr
			}
			log.Warn().Err(err).Str("addr", bag.ContractAddr).Msg("stopped contract has invalid address")
			continue
		}

		fetchCtx, cancel := context.WithTimeout(ctx, stoppedReconcileFetchTimeout)
		_, err = fetcher.FetchStorageInfo(fetchCtx, contractAddr, 0)
		cancel()
		if err != nil {
			if recordErr := s.recordStoppedReconcileFailure(bag.ContractAddr, err); recordErr != nil {
				return recordErr
			}
			log.Debug().Err(err).Str("addr", bag.ContractAddr).Msg("stopped contract is not ready to resume")
			continue
		}

		log.Info().Str("addr", bag.ContractAddr).Msg("stopped storage contract resumed")
	}

	return nil
}

func stoppedReasonRetryable(reason db.StoredBagStopReason) bool {
	switch reason {
	case db.StoredBagStopReasonUnknown,
		db.StoredBagStopReasonDownloadStalled,
		db.StoredBagStopReasonLowBalance,
		db.StoredBagStopReasonNoSpace,
		db.StoredBagStopReasonTemporaryError:
		return true
	default:
		return false
	}
}

func stoppedReasonFromError(err error) db.StoredBagStopReason {
	switch {
	case errors.Is(err, errInvalidStoredContractAddress):
		return db.StoredBagStopReasonInvalidContract
	case errors.Is(err, ErrLowBalance):
		return db.StoredBagStopReasonLowBalance
	case errors.Is(err, ErrNoSpace):
		return db.StoredBagStopReasonNoSpace
	case errors.Is(err, ErrTooBigBag):
		return db.StoredBagStopReasonBagTooBig
	case errors.Is(err, ErrTooShortSpan):
		return db.StoredBagStopReasonShortSpan
	case errors.Is(err, ErrTooLongSpan):
		return db.StoredBagStopReasonLongSpan
	case errors.Is(err, ErrTooLowRate):
		return db.StoredBagStopReasonLowRate
	case errors.Is(err, ErrLowBounty):
		return db.StoredBagStopReasonLowBounty
	case errors.Is(err, ErrNotDeployed):
		return db.StoredBagStopReasonNotDeployed
	case errors.Is(err, ErrUnsupportedContract):
		return db.StoredBagStopReasonUnsupportedContract
	case errors.Is(err, ErrProviderRemoved):
		return db.StoredBagStopReasonProviderRemoved
	default:
		return db.StoredBagStopReasonTemporaryError
	}
}

func (s *Service) recordStoppedReconcileFailure(contractAddr string, reconcileErr error) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	bag, err := s.db.GetContract(contractAddr)
	if err != nil {
		return fmt.Errorf("failed to read stopped contract: %w", err)
	}
	if bag.Status != db.StoredBagStatusStopped {
		return nil
	}

	reason := stoppedReasonFromError(reconcileErr)
	if reason == db.StoredBagStopReasonTemporaryError &&
		bag.StopReason != db.StoredBagStopReasonUnknown &&
		stoppedReasonRetryable(bag.StopReason) {
		reason = bag.StopReason
	}
	if bag.StopReason == reason {
		return nil
	}

	bag.StopReason = reason

	if err := s.db.SetContract(bag); err != nil {
		return fmt.Errorf("failed to update stopped contract reason: %w", err)
	}
	return nil
}

func (s *Service) markContractStopped(
	contractAddr string,
	bagID []byte,
	info *db.ContractInfo,
	reason db.StoredBagStopReason,
) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	stopped := db.StoredBag{
		BagID:        append([]byte(nil), bagID...),
		ContractAddr: contractAddr,
		Status:       db.StoredBagStatusStopped,
		ContractInfo: info,
		StopReason:   reason,
	}

	if err := s.db.SetContract(stopped); err != nil {
		return fmt.Errorf("failed to set stopped contract: %w", err)
	}
	return nil
}

func (s *Service) reserveContract(
	contractAddr string,
	bagID []byte,
	size uint64,
	info *db.ContractInfo,
) (db.StoredBag, bool, error) {
	s.contractCleanupMu.Lock()
	defer s.contractCleanupMu.Unlock()

	s.mx.Lock()
	defer s.mx.Unlock()

	current, err := s.db.GetContract(contractAddr)
	if err == nil && current.Status != db.StoredBagStatusStopped {
		return current, false, nil
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return db.StoredBag{}, false, fmt.Errorf("failed to read db: %w", err)
	}

	bags, err := s.db.ListContracts()
	if err != nil {
		return db.StoredBag{}, false, fmt.Errorf("failed to get current contracts: %w", err)
	}
	if size > availableStorageSpace(bags, s.spaceAllocated) {
		return db.StoredBag{}, false, ErrNoSpace
	}

	reserved := db.StoredBag{
		BagID:        append([]byte(nil), bagID...),
		Size:         size,
		ContractAddr: contractAddr,
		Status:       db.StoredBagStatusAdded,
		ContractInfo: info,
	}
	if err := s.db.SetContract(reserved); err != nil {
		return db.StoredBag{}, false, fmt.Errorf("failed to add to db: %w", err)
	}
	delete(s.warns, contractAddr)
	return reserved, true, nil
}

func availableStorageSpace(bags []db.StoredBag, allocated uint64) uint64 {
	available := allocated
	for _, bag := range bags {
		if bag.Status != db.StoredBagStatusActive && bag.Status != db.StoredBagStatusAdded {
			continue
		}
		// Versions before size reservation stored Added contracts without a bag ID
		// or size. Reserve the remainder until their worker resolves the contract.
		if bag.Status == db.StoredBagStatusAdded && len(bag.BagID) == 0 {
			return 0
		}
		if bag.Size >= available {
			return 0
		}
		available -= bag.Size
	}
	return available
}
