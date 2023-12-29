package server

import (
	"context"
	"crypto/ed25519"
	"github.com/rs/zerolog"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/tlb"
	"time"
)

type Service interface {
	AddBag(ctx context.Context, contractAddr *address.Address, size uint64) error
	GetStorageInfo() (pub ed25519.PublicKey, withdrawAddress *address.Address, minSpan, maxSpan uint32, spaceAvailable uint64, ratePerMB tlb.Coins)
}

type Server struct {
	key    ed25519.PrivateKey
	dht    *dht.Client
	gate   *adnl.Gateway
	svc    Service
	logger zerolog.Logger

	globalCtx context.Context
	closer    func()
}

func NewServer(dht *dht.Client, gate *adnl.Gateway, key ed25519.PrivateKey, svc Service, logger zerolog.Logger) *Server {
	s := &Server{
		key:    key,
		dht:    dht,
		gate:   gate,
		svc:    svc,
		logger: logger,
	}
	s.globalCtx, s.closer = context.WithCancel(context.Background())
	s.gate.SetConnectionHandler(s.bootstrapPeer)

	go func() {
		wait := 1 * time.Second
		// refresh dht records
		for {
			select {
			case <-s.globalCtx.Done():
				logger.Info().Msg("DHT updater stopped")
				return
			case <-time.After(wait):
			}

			logger.Debug().Msg("updating our address record")

			ctx, cancel := context.WithTimeout(s.globalCtx, 180*time.Second)
			err := s.updateDHT(ctx)
			cancel()

			if err != nil {
				logger.Debug().Msg("failed to update our DHT address record, will retry...")

				// on err, retry sooner
				wait = 5 * time.Second
				continue
			}
			wait = 1 * time.Minute
		}
	}()

	return s
}

func (s *Server) updateDHT(ctx context.Context) error {
	addr := s.gate.GetAddressList()

	ctxStore, cancel := context.WithTimeout(ctx, 90*time.Second)
	stored, id, err := s.dht.StoreAddress(ctxStore, addr, 10*time.Minute, s.key, 8)
	cancel()
	if err != nil && stored == 0 {
		return err
	}

	// make sure it was saved
	_, _, err = s.dht.FindAddresses(ctx, id)
	if err != nil {
		return err
	}

	s.logger.Debug().Int("nodes", stored).Msg("our address record updated")

	return nil
}

func (s *Server) bootstrapPeer(client adnl.Peer) error {
	rl := rldp.NewClientV2(client)
	rl.SetOnQuery(s.handleRLDPQuery(rl))

	return nil
}

func (s *Server) handleRLDPQuery(peer *rldp.RLDP) func(transfer []byte, query *rldp.Query) error {
	return func(transfer []byte, query *rldp.Query) error {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		switch q := query.Data.(type) {
		case StorageRatesRequest:
			pub, wa, minSpan, maxSpan, av, rate := s.svc.GetStorageInfo()

			// TODO: dynamic rate depending on size option support

			err := peer.SendAnswer(ctx, query.MaxAnswerSize, query.ID, transfer, &StorageRatesResponse{
				Available:        av >= q.Size,
				PubKey:           pub,
				RatePerMBDay:     rate.Nano().Bytes(),
				RewardAddress:    wa.Data(),
				SpaceAvailableMB: av,
				MinSpan:          minSpan,
				MaxSpan:          maxSpan,
			})
			if err != nil {
				return err
			}
		case StorageRequest:
			addr := address.NewAddress(0, 0, q.ContractAddress)

			err := s.svc.AddBag(ctx, addr, q.Size)

			if err = peer.SendAnswer(ctx, query.MaxAnswerSize, query.ID, transfer, &StorageResponse{
				Agreed: err == nil,
				Reason: err.Error(),
			}); err != nil {
				return err
			}
		}

		return nil
	}
}
