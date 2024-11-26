package cron

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
	"math/big"
	"sync"
	"time"
)

type Contract struct {
	Code    *cell.Cell
	Version int
}

var discoveryContract = address.MustParseAddr("0QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcGJH5Lec")

var cronContractCodes = func() []*Contract {
	type codeType struct {
		Hex     string
		Version int
	}
	var codes = []codeType{
		{Version: 3, Hex: "b5ee9c7241021001000253000114ff00f4a413f4bcf2c80b01020120020f020148030e0202cd040d020120050a0201200609026d3b68bb7ec07434c0fe900c005c6c2497c0f83c004875d2708024c074c7e49c16388860840b9074eb2eb8c080700038c097c0e103fcbc20070800aa10235f03f841f2d193f8276f10821005f5e100bef2e0c8f842c000f2e0c9f843c200f2e0caf84601c705f2e0cbf848c000f2e0ccf849c000f2e0cdf847f003ed4420d765f869f900f868f823f843a0f862f002f00400aa20d749c0388e3fd71d378b764657374726f798c7058e2d31f846c705f2e191f004c8801001cb05f846cf1670fa027001cb6a8210bbe2782101cb1fc98100a0fb0830db31e030915be2820afaf080be92f004dedb31005f3b513434c0007e1874c7c07e18b4c7c07e18f4c7c07e197e80007e193e90007e19b5007e19f4ffc07e1a34c24c3e1a600201200b0c005b321c4072c03e108072c7fe10c072c7fe114072c7fe113e80be11b3c5be11c0733e120072fffe124072c2727b552000353434c148700600b00404ac7cb8193e900c35d2604042eebcb81960006fd64400800e582c18480e5854108383123f200e5ffc10407a1207d013800e5b541086813f7f280e58ffc2400e5fffc2480e584e4b8fd841840041a060b7e003f08fa1020223ae43f40061f04ede21f088254143f085f089f086826100c2f2f001d31f0182102114702dbaf823f842beb08e49fa4021d70b0a8309baf2e190d31f31d1f800f823f843a0f862f002f844c2008e1fc8801001cb0501cf16f844fa027001cb6a82102e04891a01cb1fc973fb08309130e2f84773fb08309130e23af1231a"},
		{Version: 2, Hex: "b5ee9c7241021001000250000114ff00f4a413f4bcf2c80b01020120020f020148030e0202cd040d020120050a0201200609026d3b68bb7ec07434c0fe900c005c6c2497c0f83c004875d2708024c074c7e49c16388860840b9074eb2eb8c080700038c097c0e103fcbc20070800aa10235f03f841f2d193f8276f10821005f5e100bef2e0c8f842c000f2e0c9f843c200f2e0caf84601c705f2e0cbf848c000f2e0ccf849c000f2e0cdf847f003ed4420d765f869f900f868f823f843a0f862f002f00400aa20d749c0388e3fd71d378b764657374726f798c7058e2d31f846c705f2e191f004c8801001cb05f846cf1670fa027001cb6a8210bbe2782101cb1fc98100a0fb0830db31e030915be2820afaf080be92f004dedb31005f3b513434c0007e1874c7c07e18b4c7c07e18f4c7c07e197e80007e193e90007e19b5007e19f4ffc07e1a34c24c3e1a600201200b0c005b321c4072c03e108072c7fe10c072c7fe114072c7fe113e80be11b3c5be11c0733e120072fffe124072c2727b552000353434c148700600b00404ac7cb8193e900c35d2604042eebcb81960006fd64400800e582c18480e5854108383123f200e5ffc10407a1207d013800e5b541086813f7f280e58ffc2400e5fffc2480e584e4b8fd841840041a060b7e003f08fa1020223ae43f40061f04ede21f088254143f085f089f086826100bcf2f001d31f0182102114702dbaf823f842beb08e46fa403020d70b0a8309baf2e190f800f823f843a0f862f002f844c2008e1fc8801001cb0501cf16f844fa027001cb6a82102e04891a01cb1fc973fb08309130e2f84773fb08309130e2505b5d45"},
		{Version: 1, Hex: "b5ee9c7241021001000281000114ff00f4a413f4bcf2c80b01020120020f020148030e0202cd040d020120050a0201200609026d3b68bb7ec07434c0fe900c005c6c2497c0f83c004875d2708024c074c7e49c16388860840b9074eb2eb8c080700038c097c0e103fcbc20070800aa10235f03f841f2d193f8276f10821005f5e100bef2e0c8f842c000f2e0c9f843c200f2e0caf84601c705f2e0cbf848c000f2e0ccf849c000f2e0cdf847f003ed4420d765f869f900f868f823f843a0f862f002f00400aa20d749c0388e3fd71d378b764657374726f798c7058e2d31f846c705f2e193f004c8801001cb05f846cf1670fa027001cb6a8210bbe2782101cb1fc98100a0fb0830db31e030915be2820afaf080be92f004dedb31005f3b513434c0007e1874c7c07e18b4c7c07e18f4c7c07e197e80007e193e90007e19b5007e19f4ffc07e1a34c24c3e1a600201200b0c005b321c4072c03e108072c7fe10c072c7fe114072c7fe113e80be11b3c5be11c0733e120072fffe124072c2727b552000973434c148700600b00404ac7cb8193e900075d2604042eebcb8197e800c74da0070003cb819b480006387bd010c081bbcb419f40835d2c07001407000ac3cb81a35c2c13001bcb81a644c38a0006fd64400800e582c18480e5854108383123f200e5ffc10407a1207d013800e5b541086813f7f280e58ffc2400e5fffc2480e584e4b8fd841840041a19c9be003f08fa1020223ae43f40061f04ede21f088254143f085f089f086826100bcf2f001d31f0182102114702dbaf823f842beb08e46fa403020d70b0a8309baf2e190f800f823f843a0f862f002f844c2008e1fc8801001cb0501cf16f844fa027001cb6a82102e04891a01cb1fc973fb08309130e2f84773fb08309130e21caf7262"},
		{Version: 0, Hex: "b5ee9c724102100100027a000114ff00f4a413f4bcf2c80b01020120020f020148030e0202cd040d020120050a0201200609026d3b68bb7ec07434c0fe900c005c6c2497c0f83c004875d2708024c074c7e49c16388860840b9074eb2eb8c080700038c097c0e103fcbc20070800aa10235f03f841f2d193f8276f10821005f5e100bef2e0c8f842c000f2e0c9f843c200f2e0caf84601c705f2e0cbf848c000f2e0ccf849c000f2e0cdf847f003ed4420d765f869f900f868f823f843a0f862f002f00400aa20d749c0388e3fd71d378b764657374726f798c7058e2d31f846c705f2e193f004c8801001cb05f846cf1670fa027001cb6a8210bbe2782101cb1fc98100a0fb0830db31e030915be2820afaf080be92f004dedb31005f3b513434c0007e1874c7c07e18b4c7c07e18f4c7c07e197e80007e193e90007e19b5007e19f4ffc07e1a34c24c3e1a600201200b0c005b321c4072c03e108072c7fe10c072c7fe114072c7fe113e80be11b3c5be11c0733e120072fffe124072c2727b552000973434c148700600b00404ac7cb8193e900075d2604042eebcb8197e800c74da0070003cb819b480006387bd010c081bbcb419f40835d2c07001407000ac3cb81a35c2c13001bcb81a644c38a00075d64400800e582ba00e5813800e583c108383123f200e5ffc10407a1207d013800e5b541086813f7f280e58ffc2400e5fffc2480e584e4b8fd841840041a02c15e003f08fa1020223ae43f40061f04ede21f088254143f085f089f086826100a8f2f001d31f0182102114702dbaf823f842beb08e3cfa4030f800f823f843a0f862f002f844c2008e1fc8801001cb0501cf16f844fa027001cb6a82102e04891a01cb1fc973fb08309130e2f84773fb08309130e2270bd49b"},
		{Version: 0, Hex: "b5ee9c7241021001000276000114ff00f4a413f4bcf2c80b01020120020f020148030e0202cd040d020120050a0201200609026d3b68bb7ec07434c0fe900c005c6c2497c0f83c004875d2708024c074c7e49c16388860840b9074eb2eb8c080700038c097c0e103fcbc20070800aa10235f03f841f2d193f8276f10821005f5e100bef2e0c8f842c000f2e0c9f843c200f2e0caf84601c705f2e0cbf848c000f2e0ccf849c000f2e0cdf847f003ed4420d765f869f900f868f823f843a0f862f002f00400aa20d749c0388e3fd71d378b764657374726f798c7058e2d31f846c705f2e193f004c8801001cb05f846cf1670fa027001cb6a8210bbe2782101cb1fc98100a0fb0830db31e030915be2820afaf080be92f004dedb31005f3b513434c0007e1874c7c07e18b4c7c07e18f4c7c07e197e80007e193e90007e19b5007e19f4ffc07e1a34c24c3e1a600201200b0c005b321c4072c03e108072c7fe10c072c7fe114072c7fe113e80be11b3c5be11c0733e120072fffe124072c2727b552000973434c148700600b00404ac7cb8193e900075d2604042eebcb8197e800c74da0070003cb819b480006387bd010c081bbcb419f40835d2c07001407000ac3cb81a35c2c13001bcb81a644c38a0006dd64400800e582ba00e5813800e583c108383123f200e5ffb87d013800e5b541086813f7f280e58ffc2400e5fffc2480e584e4b8fd841840041a02c15e003f08fa1020223ae43f40061f04ede21f088254143f085f089f086826100a8f2f001d31f0182102114702dbaf823f842beb08e3cfa4030f800f823f843a0f862f002f844c2008e1fc8801001cb0501cf16f844fa027001cb6a82102e04891a01cb1fc973fb08309130e2f84773fb08309130e23b048606"},
	}

	var res []*Contract
	for _, code := range codes {
		b, err := hex.DecodeString(code.Hex)
		if err != nil {
			panic(fmt.Errorf("failed to parse cron contract code hex: %w", err))
		}

		c, err := cell.FromBOC(b)
		if err != nil {
			panic(fmt.Errorf("failed to parse cron contract code: %w", err))
		}
		res = append(res, &Contract{
			Code:    c,
			Version: code.Version,
		})
	}

	return res
}()

type DB interface {
	ListCronContracts() ([]db.CronContract, error)
	SetCronContract(crn db.CronContract) error
	DeleteCronContract(addr string) error
	GetCronScannerLT() (uint64, error)
	SetCronScannerLT(lt uint64) error
	GetCronWalletScannerLT() (uint64, error)
	SetCronWalletScannerLT(lt uint64) error
}

type NextTrigger struct {
	Next    *NextTrigger
	Addr    *address.Address
	Reward  tlb.Coins
	At      int64
	Version int
}

type Service struct {
	api       ton.APIClientWrapped
	wallet    *address.Address
	db        DB
	trigger   *NextTrigger
	verify    *NextTrigger
	minReward *big.Int

	mx sync.Mutex
}

func NewService(db DB, wallet *address.Address, api ton.APIClientWrapped, minReward *big.Int) *Service {
	return &Service{wallet: wallet, db: db, api: api, minReward: minReward}
}

func (s *Service) StartWalletScanner(ctx context.Context) error {
	lt, err := s.db.GetCronWalletScannerLT()
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("failed to get wallet scanner lt: %w", err)
		}
		lt = 0
	}

	ch := make(chan *tlb.Transaction)
	go s.api.SubscribeOnTransactions(ctx, s.wallet, lt, ch)

	log.Info().Uint64("lt", lt).Msg("cron wallet scanner started")

	for tx := range ch {
		func() {
			if tx.IO.In == nil || tx.IO.In.MsgType != tlb.MsgTypeInternal {
				return
			}

			in := tx.IO.In.AsInternal()
			body := in.Body.BeginParse()

			op, err := body.LoadUInt(32)
			if err != nil {
				return
			}

			if op == 0x2e04891a {
				log.Info().Str("amount", in.Amount.String()).Str("from", in.SrcAddr.String()).Msg("cron reward received")
			}
		}()

		if err = s.db.SetCronWalletScannerLT(tx.LT); err != nil {
			return fmt.Errorf("failed to set wallet scanner lt: %w", err)
		}
	}

	log.Warn().Msg("cron wallet scanner stopped")

	return nil
}

func (s *Service) StartScanner(ctx context.Context) error {
	lt, err := s.db.GetCronScannerLT()
	if err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("failed to get scanner lt: %w", err)
		}
		lt = 0
	}

	ch := make(chan *tlb.Transaction)
	go s.api.SubscribeOnTransactions(ctx, discoveryContract, lt, ch)

	log.Info().Uint64("lt", lt).Msg("cron contracts discovery started")

	for tx := range ch {
		for {
			err = func() error {
				if tx.IO.In == nil || tx.IO.In.MsgType != tlb.MsgTypeInternal {
					return nil
				}

				log.Debug().Uint64("lt", tx.LT).Msg("new tx on discovery contract")

				in := tx.IO.In.AsInternal()
				body := in.Body.BeginParse()

				op, err := body.LoadUInt(32)
				if err != nil {
					log.Debug().Err(err).Uint64("lt", tx.LT).Msg("failed to load tx in msg op")
					return nil
				}

				switch op {
				case 0xd027efe5: // op::cron_notify
					dataHash, err := body.LoadSlice(256)
					if err != nil {
						log.Debug().Err(err).Uint64("lt", tx.LT).Msg("failed to load tx in msg contract data hash")
						return nil
					}

					dataDepth, err := body.LoadUInt(10)
					if err != nil {
						log.Debug().Err(err).Uint64("lt", tx.LT).Msg("failed to load tx in msg contract data depth")
						return nil
					}

					var depth = make([]byte, 2)
					binary.BigEndian.PutUint16(depth, uint16(dataDepth))

					// emulate pruned cell
					prn := cell.FromRawUnsafe(cell.RawUnsafeCell{
						IsSpecial: true,
						LevelMask: cell.LevelMask{Mask: 1},
						BitsSz:    256 + 16 + 16,
						Data:      append([]byte{0x01, 0x01}, append(dataHash, depth...)...),
					})

					var version int
					var addrVerified bool
					for _, code := range cronContractCodes {
						sic := levelUp(cell.BeginCell().MustStoreUInt(0b00110, 5).MustStoreRef(levelUp(code.Code)).MustStoreRef(prn).EndCell())

						if address.NewAddress(0, byte(0), sic.Hash(0)).Equals(in.SrcAddr) {
							addrVerified = true
							version = code.Version
							break
						}
					}

					if !addrVerified {
						log.Debug().Uint64("lt", tx.LT).Str("addr", in.SrcAddr.String()).Msg("cron contract not verified")
						return nil
					}

					var ok bool
					var next int64
					var reward tlb.Coins
					for i := 0; i < 20; i++ {
						var retry bool
						ok, next, reward, err, retry = s.verifyContract(context.Background(), in.SrcAddr, version)
						if err != nil {
							// TODO: more reliable
							if retry {
								log.Debug().Err(err).Uint64("lt", tx.LT).Str("addr", in.SrcAddr.String()).Msg("failed to verify contract, will retry")
								time.Sleep(500 * time.Millisecond)
								continue
							}
							log.Debug().Err(err).Uint64("lt", tx.LT).Str("addr", in.SrcAddr.String()).Msg("failed to verify contract")
						}
						break
					}

					if !ok {
						log.Debug().Uint64("lt", tx.LT).Str("addr", in.SrcAddr.String()).Msg("cron contract not verified")
						return nil
					}

					if err = s.AddTrigger(db.CronContract{Version: version, ContractAddr: in.SrcAddr.String(), NextQuery: next, Reward: reward.String()}, true); err != nil {
						return err
					}

					log.Info().Uint64("lt", tx.LT).Str("addr", in.SrcAddr.String()).Int("version", version).Msg("cron contract notification discovered")
				}

				return nil
			}()
			if err != nil {
				log.Error().Err(err).Uint64("lt", tx.LT).Msg("failed to process tx")
				time.Sleep(time.Second)
				continue
			}
			break
		}

		if err = s.db.SetCronScannerLT(tx.LT); err != nil {
			return fmt.Errorf("failed to set scanner lt: %w", err)
		}
	}

	return nil
}

func (s *Service) StartSender(ctx context.Context) error {
	list, err := s.db.ListCronContracts()
	if err != nil {
		return fmt.Errorf("failed to list cron contracts: %w", err)
	}

	for _, contract := range list {
		if err = s.AddTrigger(contract, false); err != nil {
			return fmt.Errorf("failed to add trigger: %w", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}

		s.mx.Lock()
		if s.trigger == nil {
			s.mx.Unlock()
			continue
		}

		if s.trigger.Reward.Nano().Cmp(s.minReward) < 0 {
			log.Warn().Str("addr", s.trigger.Addr.String()).
				Str("reward", s.trigger.Reward.String()).
				Msg("contract dropped because reward is less than min reward")

			s.trigger = s.trigger.Next
			s.mx.Unlock()
			continue
		}

		if s.trigger.At < time.Now().Unix() {
			// we don't trust result, will verify by contract state
			err = s.api.SendExternalMessage(ctx, &tlb.ExternalMessage{
				DstAddr: s.trigger.Addr,
				Body: cell.BeginCell().
					MustStoreUInt(0x2114702d, 32). // trigger op
					MustStoreAddr(s.wallet).
					MustStoreUInt(uint64(time.Now().Unix()), 32). // to not ignore external by ls
					EndCell(),
			})
			if err != nil {
				log.Debug().Str("addr", s.trigger.Addr.String()).Err(err).Int64("want_at", s.trigger.At).Msg("trigger was not sent, we will reverify state")
			} else {
				log.Info().Str("addr", s.trigger.Addr.String()).Int64("want_at", s.trigger.At).Msg("trigger sent")
			}

			old := s.trigger
			s.trigger = s.trigger.Next

			go func() {
				// wait for potential commit
				time.Sleep(15 * time.Second)
				s.addVerify(old)
			}()
		}
		s.mx.Unlock()
	}
}

func (s *Service) StartVerifier(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}

		s.mx.Lock()
		if s.verify == nil {
			s.mx.Unlock()
			continue
		}

		err := func() error {
			tCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
			defer cancel()

			// TODO: not block
			ok, next, reward, err, retry := s.verifyContract(tCtx, s.verify.Addr, s.verify.Version)
			if err != nil {
				if retry {
					return err
				} else {
					log.Warn().Err(err).Str("addr", s.verify.Addr.String()).Msg("failed to verify cron contract, not retryable error")
				}
			} else if !ok {
				log.Debug().Str("addr", s.verify.Addr.String()).Msg("cron contract removed")
				_ = s.db.DeleteCronContract(s.verify.Addr.String())
			} else {
				if err = s.addTrigger(db.CronContract{Version: s.verify.Version, ContractAddr: s.verify.Addr.String(), NextQuery: next, Reward: reward.String()}, true); err != nil {
					return err
				}
				log.Debug().Str("addr", s.verify.Addr.String()).Int64("next", next).Msg("adding contract back to trigger, valid for the next trigger")
			}

			s.verify = s.verify.Next
			return nil
		}()
		if err != nil {
			log.Debug().Err(err).Str("addr", s.verify.Addr.String()).Msg("failed to verify cron contract, will be retried")
		}
		s.mx.Unlock()
	}
}

func (s *Service) addTrigger(c db.CronContract, toDB bool) error {
	nextTrigger := &NextTrigger{
		Addr:    address.MustParseAddr(c.ContractAddr),
		At:      c.NextQuery,
		Reward:  tlb.MustFromTON(c.Reward),
		Version: c.Version,
	}

	if s.trigger == nil || c.NextQuery < s.trigger.At {
		nextTrigger.Next = s.trigger
		s.trigger = nextTrigger
	} else {
		current := s.trigger
		for current.Next != nil && current.Next.At < c.NextQuery {
			current = current.Next
		}

		if current.Addr.String() == c.ContractAddr {
			// already added
			log.Debug().Str("addr", c.ContractAddr).Msg("already added")
			return nil
		}

		nextTrigger.Next = current.Next
		current.Next = nextTrigger
	}

	if toDB {
		if err := s.db.SetCronContract(c); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) AddTrigger(c db.CronContract, toDB bool) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	return s.addTrigger(c, toDB)
}

func (s *Service) addVerify(trig *NextTrigger) {
	trig.Next = nil

	if s.verify == nil || trig.At < s.verify.At {
		trig.Next = s.verify
		s.verify = trig
	} else {
		current := s.verify
		for current.Next != nil && current.Next.At < trig.At {
			current = current.Next
		}
		trig.Next = current.Next
		current.Next = trig
	}
}

func methodByVersion(version int) string {
	switch version {
	case 0:
		return "info"
	case 1:
		return "getCronInfo"
	default:
		return "get_cron_info"
	}
}

func (s *Service) verifyContract(ctx context.Context, addr *address.Address, version int) (bool, int64, tlb.Coins, error, bool) {
	master, err := s.api.GetMasterchainInfo(ctx)
	if err != nil {
		return false, 0, tlb.ZeroCoins, err, true
	}

	res, err := s.api.RunGetMethod(ctx, master, addr, methodByVersion(version))
	if err != nil {
		if _, ok := err.(ton.ContractExecError); ok {
			// not initialized contract or something failed
			return false, 0, tlb.ZeroCoins, nil, false
		}
		return false, 0, tlb.ZeroCoins, fmt.Errorf("failed to get cron contract info: %w", err), true
	}

	nextCallAt, err := res.Int(0)
	if err != nil {
		return false, 0, tlb.ZeroCoins, fmt.Errorf("failed to get cron contract next call time: %w", err), false
	}

	reward, err := res.Int(1)
	if err != nil {
		return false, 0, tlb.ZeroCoins, fmt.Errorf("failed to get cron contract reward: %w", err), false
	}

	balanceAfterNextCall, err := res.Int(2)
	if err != nil {
		return false, 0, tlb.ZeroCoins, fmt.Errorf("failed to get cron contract balance after next call: %w", err), false
	}

	if reward.Cmp(s.minReward) < 0 {
		log.Debug().Str("addr", addr.String()).Str("min_reward", tlb.FromNanoTON(s.minReward).String()).Str("reward", tlb.FromNanoTON(reward).String()).Msg("reward is too low")
		return false, 0, tlb.ZeroCoins, nil, false
	}

	// should have some amount for fees
	if balanceAfterNextCall.Cmp(tlb.MustFromTON("0.01").Nano()) <= 0 {
		// no money for next call
		return false, 0, tlb.ZeroCoins, nil, false
	}

	return true, nextCallAt.Int64(), tlb.FromNanoTON(reward), nil, false
}

func levelUp(c *cell.Cell) *cell.Cell {
	u := c.ToRawUnsafe()
	u.LevelMask.Mask = 1
	return cell.FromRawUnsafe(u)
}
