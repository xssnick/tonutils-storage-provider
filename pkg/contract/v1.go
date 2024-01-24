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

var _V1CodeHex, _ = hex.DecodeString("b5ee9c7241021101000363000114ff00f4a413f4bcf2c80b01020162090202014804030089b8d31ed44d0d3ff31f404306f007f8e2a228307f47c6fa5208e1b02d33fd31fd33fd430d0d31ffa00302550554414036f06136f8c029132e201b3e630318201247ded43d880201580605005db006bb513434ffcc7d010c20c1fd039be87cb86534cff4c7f4cff5d33434c7fe800c3e09dbc420821312d028440d6002014808070026a87df8276f1082084c4b40a120c100923070de002aa9e9ed44d0d3ff71d721fa40d33fd31fd3ff304130039ed001d0d3030171b0925f04e0fa403020fa4430c000f2e06f21c700925f04e001d31f21c000925f05e0d33f22821048f548cebae3023133332282103dc680aeba9131e30d01821061fff683bae302300e0b0a007eed44d0d3ff71d721fa40305122c705f2e19182084c4b4070fb02f8258210b6236d63708010c8cb055005cf1624fa0214cb6a13cb1f12cb3fcbffc98306fb0002fced44d0d3fff404fa40d33fd31fd3ffd307305374c705f2e19120c00099955320ac24b991a4e8de08f404307f8e3a268307f47c6fa5208e2b53138307f40e6fa1b399303252088307f45b308e1403d74cd05003c705b39852088307f45b3007de07e2079132e201b3e630708ae6318308bef2d19605c8cbff14f40058cf160d0c0018cb3fcb1fcbff12cb07c9ed5400a8018307f4966fa5208e4404a453198307f40e6fa131b38e3102d31ffa00d121c000f2d19720c000f2d19801c8cb1f01fa02c9843ff8117029f811c8cb3fcb1fcb3fcc40198307f44307926c21e202926c21e2b31201fe6c12d3ff8308d71820f901541023f910f2e191d33fed44d0d3fff404fa40d33fd31fd3ffd3073053958307f40e6fa1f2e191d33fd31fd33f0cbaf2e1910ad74c20d0d31ffa0030111082084c4b40a001111101a120c100923070def823500ca1205611bc9130925710e2525fa8500f8102a3aa1aa9845390b9923028de19a10f01fc82084c4b40a070fb0206d74c5446d054530052a011103302d739b3f24dd30701c303f24e20d70bff5005bdf2d09703d5315023a904219b01a55cad71b013d748d059e45bd7498307baf290f823843ff81122f811c8cb3f12cb1fcb3f1acc50628307f4438210a91baf56708010c8cb055009cf1628fa0218cb6a17cb1f1510003ccb3fc98306fb0003c8cbff14f40001cf1613cb3f13cb1fcbffcb07c9ed549622ce8c")
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
	Key         []byte
	LastProofAt time.Time
	ByteToProof uint64
	MaxSpan     uint32
	RatePerMB   tlb.Coins
	Nonce       uint64
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
		MustStoreUInt(0x3dc680ae, 32).
		MustStoreUInt(uint64(rand.Int63()), 64).
		MustStoreDict(providersDict).
		EndCell()

	contractAddr = address.NewAddress(0, 0, stateCell.Hash())
	return contractAddr, stateInit, body, nil
}

func PrepareWithdrawalRequest(torrentHash, merkleHash []byte, dataSize uint64, pieceSize uint32, ownerAddr *address.Address) (contractAddr *address.Address, body *cell.Cell, err error) {
	data, err := tlb.ToCell(StorageV1{
		TorrentHash: torrentHash,
		OwnerAddr:   ownerAddr,
		DataSize:    dataSize,
		PieceSize:   pieceSize,
		MerkleHash:  merkleHash,
	})
	if err != nil {
		return nil, nil, err
	}

	stateInit := &tlb.StateInit{
		Code: V1Code,
		Data: data,
	}

	stateCell, err := tlb.ToCell(stateInit)
	if err != nil {
		return nil, nil, err
	}
	contractAddr = address.NewAddress(0, 0, stateCell.Hash())
	body = cell.BeginCell().MustStoreUInt(0x61fff683, 32).MustStoreUInt(0, 64).EndCell()
	return contractAddr, body, nil
}

var ErrProviderNotFound = errors.New("provider not found")
var ErrNotDeployed = errors.New("not deployed")

func GetProviderDataV1(ctx context.Context, api ton.APIClientWrapped, master *ton.BlockIDExt, contractAddr *address.Address, key []byte) (*ProviderDataV1, tlb.Coins, error) {
	res, err := api.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_provider_info", new(big.Int).SetBytes(key))
	if err != nil {
		lgErr, ok := err.(ton.ContractExecError)
		if ok && lgErr.Code == 404 {
			return nil, tlb.ZeroCoins, ErrProviderNotFound
		}
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to run contract method get_provider_info: %w", err)
	}

	nonce, err := res.Int(0)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info nonce returned value: %w", err)
	}

	lastProofAt, err := res.Int(1)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info last proof time returned value: %w", err)
	}

	byteToProof, err := res.Int(2)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info byte to proof returned value: %w", err)
	}

	span, err := res.Int(3)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info span returned value: %w", err)
	}

	ratePerMB, err := res.Int(4)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info rate returned value: %w", err)
	}

	contractAvailableBalance, err := res.Int(5)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_provider_info contract available balance returned value: %w", err)
	}

	return &ProviderDataV1{
		Key:         key,
		LastProofAt: time.Unix(lastProofAt.Int64(), 0),
		ByteToProof: byteToProof.Uint64(),
		MaxSpan:     uint32(span.Uint64()),
		RatePerMB:   tlb.FromNanoTON(ratePerMB),
		Nonce:       nonce.Uint64(),
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

func GetProvidersV1(ctx context.Context, api ton.APIClientWrapped, master *ton.BlockIDExt, contractAddr *address.Address) ([]ProviderDataV1, tlb.Coins, error) {
	res, err := api.WaitForBlock(master.SeqNo).RunGetMethod(ctx, master, contractAddr, "get_providers")
	if err != nil {
		lgErr, ok := err.(ton.ContractExecError)
		if ok && lgErr.Code == ton.ErrCodeContractNotInitialized {
			return nil, tlb.ZeroCoins, ErrNotDeployed
		}
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to run contract method get_providers: %w", err)
	}

	list, err := res.Tuple(0)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_providers list value: %w", err)
	}

	balance, err := res.Int(1)
	if err != nil {
		return nil, tlb.ZeroCoins, fmt.Errorf("failed to read get_providers balance value: %w", err)
	}

	var providers []ProviderDataV1
	for _, v := range list {
		p, ok := v.([]any)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value")
		}
		if len(p) != 6 {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value len")
		}

		bKey := make([]byte, 32)
		key, ok := p[0].(*big.Int)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value 'key' param")
		}
		key.FillBytes(bKey)

		ratePerMb, ok := p[1].(*big.Int)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value 'ratePerMb' param")
		}

		maxSpan, ok := p[2].(*big.Int)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value 'maxSpan' param")
		}

		lastProofTime, ok := p[3].(*big.Int)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value 'lastProofTime' param")
		}

		byteToProof, ok := p[4].(*big.Int)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value 'byteToProof' param")
		}

		nonce, ok := p[5].(*big.Int)
		if !ok {
			return nil, tlb.ZeroCoins, fmt.Errorf("icorrect provider value 'nonce' param")
		}

		providers = append(providers, ProviderDataV1{
			Key:         bKey,
			LastProofAt: time.Unix(lastProofTime.Int64(), 0),
			ByteToProof: byteToProof.Uint64(),
			MaxSpan:     uint32(maxSpan.Uint64()),
			RatePerMB:   tlb.FromNanoTON(ratePerMb),
			Nonce:       nonce.Uint64(),
		})
	}

	return providers, tlb.FromNanoTON(balance), nil
}
