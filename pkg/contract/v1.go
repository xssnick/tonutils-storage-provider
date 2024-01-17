package contract

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"math/big"
	"math/rand"
	"time"
)

var _V1CodeHex, _ = hex.DecodeString("b5ee9c7241021101000343000114ff00f4a413f4bcf2c80b01020162090202014804030087b8d31ed44d0d3ff31f404306f007f8e30228307f47c6fa5208e2102d33fd31fd430d0d31ffa00308309c8cb0a5250cbffc9d0255e406f06136f8c029132e201b3e63031802015806050075b006bb513434ffcc7d010c148420c1fd039be87cb86534cff4c7f5d33434c7fe800c3e09dbc420822625a02860c27232c285b2fff274040d5540a002014808070018a87df8276f108208989680a1002aa9e9ed44d0d3ff71d721fa40d33fd31fd3ff304130039cd001d0d3030171b0925f04e0fa403021c700925f04e020fa4401c000f2e06f02d31f21c000925f06e0d33f228210419d5d4dbae302316c33218210e4748df2ba9130e30d821019f937eabae302300e0b0a007eed44d0d3ff71d721fa40305122c705f2e191820898968070fb02f8258210b6236d63708010c8cb055005cf1624fa0214cb6a13cb1f12cb3fcbffc98306fb0002fced44d0d3fff404fa40d33fd31fd3ffd3073020c00099955320ac24b991a4e8de5394c705f2e19107f404307f8e2c268307f47c6fa5208e1d53138307f40e6fa1b304d74cd001c705b313b19852088307f45b3007de9132e201b3e630820898968070fb02708ae6318308bef2d19605c8cbff14f40058cf16cb3fcb1fcbff0d0c000acb07c9ed5400ac018307f4966fa5208e4604a453198307f40e6fa131b38e3302d31ffa00d121c000f2d19720c000f2d198830902c8cb1f01fa02cb0a5210cbffc97028f811c8cb3fcb1fcc40198307f44307926c21e202926c21e2b31201ee32ed44d0d3fff404fa40d33fd31fd3ffd3073053a58307f40e6fa1f2e191d33fd31fd74c20d0d31ffa003011108208989680a001111101a120c100923070def8235003a1205611bc9130925710e2526fa8500f8102a3aa1aa98453e0b992302dde1ea18208989680a070fb0208d74c543c315464b011100f01fe3302d739b3f24dd30701c303f24e20d70bff5005bdf2d09703d5315023a904219b01a55cad71b013d748d059e45b20d7498307ba01d74ac000b0f290f82322f811c8cb3fcb1f1acc40838307f4438210a91baf56708010c8cb055008cf1627fa0217cb6a16cb1f13cb3fc98306fb00c8cbff13f40058cf1612cb3f12cb1f1210000ecbffcb07c9ed54a77b4f91")
var V1Code, _ = cell.FromBOC(_V1CodeHex)

type StorageV1 struct {
	TorrentHash     []byte           `tlb:"bits 256"`
	ActiveProviders *cell.Dictionary `tlb:"dict 256"`
	OwnerAddr       *address.Address `tlb:"addr"`
	DataSize        uint64           `tlb:"## 64"`
	PieceSize       uint32           `tlb:"## 32"`
	MerkleHash      []byte           `tlb:"bits 256"`
	KeyLen          uint8            `tlb:"## 8"`
}

type ProviderV1 struct {
	Address       *address.Address
	MaxSpan       uint32
	PricePerMBDay tlb.Coins
}

type ProviderDataV1 struct {
	Key          []byte
	LastProofAt  time.Time
	ByteToProof  uint64
	MaxSpan      uint32
	RatePerMB    tlb.Coins
	ProviderAddr *address.Address
}

type StorageDataV1 struct {
	TorrentHash []byte
	Size        uint64
	ChunkSize   uint64
	OwnerAddr   *address.Address
	MerkleHash  []byte
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
		err = providersDict.SetIntKey(new(big.Int).SetBytes(provider.Address.Data()),
			cell.BeginCell().
				MustStoreUInt(uint64(provider.MaxSpan), 32).
				MustStoreBigCoins(provider.PricePerMBDay.Nano()).
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

var ErrProviderNotFound = errors.New("provider not found")

func GetProviderDataV1(ctx context.Context, api ton.APIClientWrapped, master *ton.BlockIDExt, contractAddr *address.Address, key []byte) (*ProviderDataV1, tlb.Coins, error) {
	res, err := api.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_provider_info", new(big.Int).SetBytes(key))
	if err != nil {
		lgErr, ok := err.(ton.ContractExecError)
		if ok && lgErr.Code == 404 {
			return nil, tlb.ZeroCoins, ErrProviderNotFound
		}
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to run contract method get_provider_info: %w", err)
	}

	lastProofAt, err := res.Int(0)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info last proof time returned value: %w", err)
	}

	byteToProof, err := res.Int(1)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info byte to proof returned value: %w", err)
	}

	span, err := res.Int(2)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info span returned value: %w", err)
	}

	ratePerMB, err := res.Int(3)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info rate returned value: %w", err)
	}

	providerAddrSlice, err := res.Slice(4)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info addr returned value: %w", err)
	}
	providerAddr, err := providerAddrSlice.LoadAddr()
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to parse provider addr returned value: %w", err)
	}

	contractAvailableBalance, err := res.Int(5)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info contract available balance returned value: %w", err)
	}

	return &ProviderDataV1{
		Key:          key,
		LastProofAt:  time.Unix(lastProofAt.Int64(), 0),
		ByteToProof:  byteToProof.Uint64(),
		MaxSpan:      uint32(span.Uint64()),
		RatePerMB:    tlb.FromNanoTON(ratePerMB),
		ProviderAddr: providerAddr,
	}, tlb.FromNanoTON(contractAvailableBalance), nil
}

func GetStorageInfoV1(ctx context.Context, api ton.APIClientWrapped, master *ton.BlockIDExt, contractAddr *address.Address) (*StorageDataV1, error) {
	res, err := api.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_storage_info")
	if err != nil {
		return nil, fmt.Errorf("failed to run contract method get_storage_info: %w", err)
	}

	tHash := make([]byte, 32)
	torrentHash, err := res.Int(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read get_storage_info torrentHash: %w", err)
	}
	torrentHash.FillBytes(tHash)

	size, err := res.Int(1)
	if err != nil {
		return nil, fmt.Errorf("failed to read get_storage_info size returned value: %w", err)
	}

	chunk, err := res.Int(2)
	if err != nil {
		return nil, fmt.Errorf("failed to read get_storage_info chunk returned value: %w", err)
	}

	addrSlice, err := res.Slice(3)
	if err != nil {
		return nil, fmt.Errorf("failed to read get_storage_info addr returned value: %w", err)
	}
	addr, err := addrSlice.LoadAddr()
	if err != nil {
		return nil, fmt.Errorf("failed to parse addr returned value: %w", err)
	}

	mHash := make([]byte, 32)
	merkleHash, err := res.Int(4)
	if err != nil {
		return nil, fmt.Errorf("failed to read get_storage_info merkleHash: %w", err)
	}
	merkleHash.FillBytes(mHash)

	return &StorageDataV1{
		TorrentHash: tHash,
		Size:        size.Uint64(),
		ChunkSize:   chunk.Uint64(),
		OwnerAddr:   addr,
		MerkleHash:  mHash,
	}, nil
}

func GetProvidersV1(ctx context.Context, api ton.APIClientWrapped, master *ton.BlockIDExt, contractAddr *address.Address) ([]ProviderDataV1, error) {
	res, err := api.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_providers")
	if err != nil {
		return nil, fmt.Errorf("failed to run contract method get_providers: %w", err)
	}

	list, err := res.Tuple(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read get_providers list value: %w", err)
	}

	var providers []ProviderDataV1
	for _, v := range list {
		p, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value")
		}
		if len(p) != 6 {
			return nil, fmt.Errorf("icorrect provider value len")
		}

		bKey := make([]byte, 32)
		key, ok := p[0].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value 'key' param")
		}
		key.FillBytes(bKey)

		addrSlice, ok := p[1].(*cell.Slice)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value 'addr' param")
		}
		addr, err := addrSlice.LoadAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to parse addr returned value: %w", err)
		}

		ratePerMb, ok := p[2].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value 'ratePerMb' param")
		}

		maxSpan, ok := p[3].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value 'maxSpan' param")
		}

		lastProofTime, ok := p[4].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value 'lastProofTime' param")
		}

		byteToProof, ok := p[5].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("icorrect provider value 'byteToProof' param")
		}

		providers = append(providers, ProviderDataV1{
			Key:          bKey,
			LastProofAt:  time.Unix(lastProofTime.Int64(), 0),
			ByteToProof:  byteToProof.Uint64(),
			MaxSpan:      uint32(maxSpan.Uint64()),
			RatePerMB:    tlb.FromNanoTON(ratePerMb),
			ProviderAddr: addr,
		})
	}

	return providers, nil
}
