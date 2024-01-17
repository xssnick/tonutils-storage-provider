package server

import "github.com/xssnick/tonutils-go/tl"

func init() {
	tl.Register(StorageRatesRequest{}, "storageProvider.ratesRequest size:long = storageProvider.RatesRequest")
	tl.Register(StorageRatesResponse{}, "storageProvider.ratesResponse available:Bool key:int256 rate_per_mb_day:bytes "+
		"reward_address:int256 space_available_mb:long min_span:int max_span:int = storageProvider.RatesResponse")
	tl.Register(StorageRequest{}, "storageProvider.storageRequest contract_address:int256 size:long = storageProvider.StorageRequest")
	tl.Register(StorageResponse{}, "storageProvider.storageResponse agreed:Bool reason:string = storageProvider.StorageResponse")
}

type StorageRatesRequest struct {
	Size uint64 `tl:"long"`
}

type StorageRatesResponse struct {
	Available        bool   `tl:"bool"`
	RatePerMBDay     []byte `tl:"bytes"`
	Key              []byte `tl:"int256"`
	SpaceAvailableMB uint64 `tl:"long"`
	MinSpan          uint32 `tl:"int"`
	MaxSpan          uint32 `tl:"int"`
}

type StorageRequest struct {
	ContractAddress []byte `tl:"int256"`
}

type StorageResponse struct {
	Agreed bool   `tl:"bool"`
	Reason string `tl:"string"`
}
