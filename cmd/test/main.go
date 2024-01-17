package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/pkg/contract"
	"math/big"
	"os"
)

func main() {
	var lsCfg *liteclient.GlobalConfig

	lsCfg, err := liteclient.GetConfigFromUrl(context.Background(), "https://ton.org/testnet-global.config.json")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to download ton config, we will take it from static cache")
	}

	lc := liteclient.NewConnectionPool()
	if err = lc.AddConnectionsFromConfig(context.Background(), lsCfg); err != nil {
		log.Fatal().Err(err).Msg("failed to add liteserver connections from ton config")
	}

	api := ton.NewAPIClient(lc).WithRetry(1)

	seed := make([]byte, 32)
	seed[0] = 1
	kk := ed25519.NewKeyFromSeed(seed)
	w, err := wallet.FromPrivateKey(api, kk, wallet.V3R2)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init wallet")
	}

	println(w.WalletAddress().String())

	sz := uint64(46749448209)
	psz := uint32(128 * 1024)
	hash, _ := hex.DecodeString("70b9e62c6123d15ae42b23e8857c9a4b12a9997606f72cf9f548fe09c1c25cb5")
	merkle, _ := hex.DecodeString("acaaf3306ce628b18c62bd074b263c2354b1fd156eab189d4398db02f40ed09c")

	providerKey := address.MustParseAddr("UQA-4idHnBmZDJSe28OGrBK7DZDw7R6XlScT0qeGeq7wT3su")
	addr, si, body, err := contract.PrepareV1DeployData(hash, merkle, sz, psz, w.WalletAddress(), []contract.ProviderV1{
		{
			Address:       providerKey,
			MaxSpan:       200,
			PricePerMBDay: tlb.MustFromTON("0.0005"),
		},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to build contract data")
	}
	_ = si
	_ = body

	ctx := context.Background()
	for {
		ctx, _ = api.Client().StickyContextNextNode(ctx)
		//if len(os.Args) > 1 && os.Args[1] == "deploy" {
		_, _, _, err = w.DeployContractWaitTransaction(ctx, tlb.MustFromTON("0.5"), body, si.Code, si.Data)
		if err != nil {
			log.Error().Err(err).Msg("failed to deploy contract")
			continue
		}

		println("contract deployed", addr.String())
		//}
		break
	}

	for {
		ctx, _ = api.Client().StickyContextNextNode(ctx)
		master, err := api.GetMasterchainInfo(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get masterchain")
		}

		res, err := api.RunGetMethod(ctx, master, addr, "get_providers")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get_providers")
		}

		json.NewEncoder(os.Stdout).Encode(res.AsTuple())
		break
	}

	for {
		ctx, _ = api.Client().StickyContextNextNode(ctx)
		master, err := api.GetMasterchainInfo(ctx)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get masterchain")
		}

		pr, _ := hex.DecodeString("b5ee9c7201021801000212000946031d35ba415ceda44cc2df559c07033cc8132f4865d0777303fb00214ec1d6d312000b012200030228480101cedb85bc93dacf749d8840b43581957f4bf3fbe4d514529c1a12b556dc60ff72000a22001704220016052200070628480101e17914bff3289aea38efc0202723630ffd0d9e87cf56c158e93db049995c4b7e00072200150822000a092848010154e0b479efe582bd0cbd58294b92023c0f77f9df5aae91240609423756a94b93000522000c0b2848010166a4e4b4a72db9f8d69bbbfc0ec96727441e364ae90bf25660ab9ea455011976000422000e0d28480101741047117ad1c9d9a2caa42e5fccd0cc1dd05a20bd58c3a3d97905fc2f09dc8000032200140f22001110284801019d067ca04c96c43c91ad4c3aef5b1de262f8325c123658426cf8fe6fd8183a0e0001020013120040aea107fb7ee4a3fe4366f44c99423d45bef07a75685bdeab3f81ebcd58e1094f0040652a31eb2e965354cae0ec8d9cded623a5132717bd1246acb3a810b8cee78ebd28480101f4109b87a9cea96160d66e622c8d0d83f08cf909a0a2dab1febbfe383bccd1730002284801018c460ea35a756ee664f9c5a5caaf0c920aff751333d9980c50c713f590ff510f000628480101a62b564a6cfddbb1baa2c7bbbdb2a03b7cf132e3856fa6b5466a347de20aeb490008284801011a0c94457b849dcd8b2999eee4bda3e54e54f022a15b839806a9e7d9c41607810009")
		pf, _ := cell.FromBOC(pr)

		aa, _ := api.GetAccount(ctx, master, addr)
		println(aa.Data.Dump())
		println(pf.Dump())
		res, err := api.RunGetMethod(ctx, master, addr, "verify_proof", new(big.Int).SetBytes(providerKey.Data()), pf)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to verify_proof")
		}

		json.NewEncoder(os.Stdout).Encode(res.AsTuple())
		break
	}
}
