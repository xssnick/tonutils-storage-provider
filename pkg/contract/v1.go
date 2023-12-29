package contract

import (
	"encoding/hex"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"math/big"
	"math/rand"
)

var _V1CodeHex, _ = hex.DecodeString("b5ee9c7241021901000501000114ff00f4a413f4bcf2c80b01020120080202bcf26c21d31fd33fed44d0d3fff404fa40d33fd31ffa00d3ffd3073008d3ff8308d718d43020f900541023f910f2e191d0d3ff5119baf2e19153178307f40e6fa1f2e1912c821046ed2e94bae3023b0b8210419d5d4dbae3025f0c840ff2f0060302fc09d33fd31fd31ffa00d74c20d0d31ffa00301110d30701c002f2e191d33f5117baf2e191d74cf8235162a016b9f2d1ae52901110a8500f8102a3aa1aa984820898968027a021a001111001a1c100f2d1aff800547a98547a982a56125614f8235450cb5619ed44ed45ed47915bed67ed65ed64800d7fed118aed41edf10105040066f2ff29f811c8cb3f14cb1f12cb1f01fa02cc40188307f44307c8cbff17f4005004cf1612cb3fcb1f01fa0212cbffcb07c9ed54004454444054688052e6f00152042da0502da0108c107b106a105910481047102644030201fe3c3c0ad65fd31ffa00d74c20d08020d721fa0031fa40300fd30701c001f2e191d31f3023baf2e191218209312d00b9f2d195f8002171fb025055a18210a91baf56708010c8cb05011110cf162ffa021fcb6a1ecb1f1bcb3fc98306fb00c801cf1619cb1f70fa02cc40848307f44303c8cbff13f40058cf16cb3f13cb1f5003070014fa0212cbffcb07c9ed5402014812090201200b0a0059beb10f6a26869ff98fa027d2018e99fe98ffd0018e9ffe9839828324183fa0737d0f970ca699f98209a7800bfc0201200d0c0095b8d31ed44d0d3ff31f404fa40318060d721fa00306f007f8e2d238307f47c6fa5208e1e028040d721d31fd31ffa00d430d0d31ffa00fa4030265e506f07136f8c029132e201b3e6306c1280201580f0e0083b006bb513434ffcc7d013e900c601835c87e800c1660c1fd039be87cb86534cff4c7f4c7fe8035d33434c7fe803e900c3e09dbc40220822625a0280628578cd04c2002014811100040a87ded44d0810101d721fa40318060d721fa0030f8276f10018208989680a0a10030a9e9ed44d0d3ff71d721fa40d33fd31ffa0031d3ff3041300202cf1413008f0cc0b5ce6cfc9534c1c070c0fc950835c2ffd4016f7c9500f54c5408ea4124c870802384c8696b94842c2500b5d37424c0b54c788069563a16c835d260c1ee8075d2b0002c3ca560026f0ccc7434c0c05c6c2456f83e900c0871c02456f80074c7c870002497c0f834cfcc486084391d237caea44c38c36084067e4dfaaeb8c08c2016150090ed44d0d3ff71d721fa408040d721fa00305131c705f2e19182089896805003a070fb02f8258210b6236d63708010c8cb055005cf1624fa0214cb6a13cb1f12cb3fcbffc98306fb0002bced44d0d3fff404fa40d33fd31ffa00d3ffd3073020c00099955330ac25b991a4e8de53a5c705f2e19108f404307f8ae630820898968023a070fb02708ae6318308bcf2d19506c8cbff15f4005003cf16cb3fcb1f01fa02cbffcb07c9ed54181700b2018307f4966fa5208e4904a4531a8307f40e6fa131b38e3602d31ffa00fa40d122c000f2d1c321c000f2d1c402c8cb1f01fa0201cf16c9705309f811c8cb3fcb1fcb1f70fa02cc401a8307f44308926c21e202926c21e2b31200f6278307f47c6fa5208e6c53138307f40e6fa1b324d74cd058c705b3b18e55028306d721fa00d430d08020d721fa0031fa40305161a1218209312d00b9968209312d0032def8258210b6236d63708010c8cb05500acf165004fa0218cb6a12cb1f16cb3f52a0cbffc970fb0052098307f45b30089132e29132e201b318d8e150")
var V1Code, _ = cell.FromBOC(_V1CodeHex)

type StorageV1 struct {
	TorrentHash     []byte           `tlb:"bits 256"`
	ActiveProviders *cell.Dictionary `tlb:"dict 256"`
	OwnerAddr       *address.Address `tlb:"addr"`
	DataSize        uint64           `tlb:"## 64"`
	PieceSize       uint32           `tlb:"## 32"`
	DebtAmount      tlb.Coins        `tlb:"."`
	MerkleHash      []byte           `tlb:"bits 256"`
	KeyLen          uint8            `tlb:"## 8"`
}

type ProviderV1 struct {
	Key []byte

	Span          uint32
	PricePerMBDay tlb.Coins
}

func PrepareV1DeployData(torrentHash, merkleHash []byte, dataSize uint64, pieceSize uint32, ownerAddr *address.Address, providers []ProviderV1) (contractAddr *address.Address, stateInit *tlb.StateInit, body *cell.Cell, err error) {
	data, err := tlb.ToCell(StorageV1{
		TorrentHash: torrentHash,
		OwnerAddr:   ownerAddr,
		DataSize:    dataSize,
		PieceSize:   pieceSize,
		MerkleHash:  merkleHash,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	stateInit = &tlb.StateInit{
		Code: V1Code,
		Data: data,
	}

	stateCell, err := tlb.ToCell(stateInit)
	if err != nil {
		return nil, nil, nil, err
	}

	providersDict := cell.NewDict(256)

	for _, provider := range providers {
		err = providersDict.SetIntKey(new(big.Int).SetBytes(provider.Key),
			cell.BeginCell().
				MustStoreUInt(uint64(provider.Span), 32).
				MustStoreBigCoins(provider.PricePerMBDay.Nano()).
				MustStoreAddr(address.MustParseAddr("EQBx6tZZWa2Tbv6BvgcvegoOQxkRrVaBVwBOoW85nbP37_Go")).
				EndCell())
		if err != nil {
			return nil, nil, nil, err
		}
	}

	body = cell.BeginCell().
		MustStoreUInt(0xe4748df2, 32).
		MustStoreUInt(uint64(rand.Int63()), 64).
		MustStoreDict(providersDict).
		EndCell()

	contractAddr = address.NewAddress(0, 0, stateCell.Hash())
	return contractAddr, stateInit, body, nil
}
