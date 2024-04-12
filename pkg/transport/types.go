package transport

import "github.com/xssnick/tonutils-go/tl"

func init() {
	tl.Register(StorageRatesRequest{}, "storageProvider.ratesRequest size:long = storageProvider.RatesRequest")
	tl.Register(StorageRatesResponse{}, "storageProvider.ratesResponse available:Bool key:int256 rate_per_mb_day:bytes "+
		"reward_address:int256 space_available_mb:long min_span:int max_span:int = storageProvider.RatesResponse")
	tl.Register(StorageRequest{}, "storageProvider.storageRequest contract_address:int256 size:long = storageProvider.StorageRequest")
	tl.Register(StorageResponse{}, "storageProvider.storageResponse status:string reason:string downloaded:long = storageProvider.StorageResponse")
	tl.Register(StorageADNLProofRequest{}, "storageProvider.storageAdnlProofRequest contract_address:int256 = storageProvider.StorageAdnlProofRequest")
	tl.Register(StorageADNLProofResponse{}, "storageProvider.storageAdnlProofResponse storage_key:int256 signature:bytes = storageProvider.StorageAdnlProofResponse")

	tl.Register(ProviderDHTRecord{}, "storageProvider.dhtRecord adnl_key:int256 = storageProvider.DHTRecord")
	tl.Register(ADNLProofScheme{}, "storage.tonutils.adnlProviderProof provider_key:int256 = storage.tonutils.AdnlProviderProof")
}

type StorageRatesRequest struct {
	Size uint64 `tl:"long"`
}

type StorageRatesResponse struct {
	Available        bool   `tl:"bool"`
	RatePerMBDay     []byte `tl:"bytes"`
	MinBounty        []byte `tl:"bytes"`
	SpaceAvailableMB uint64 `tl:"long"`
	MinSpan          uint32 `tl:"int"`
	MaxSpan          uint32 `tl:"int"`
}

type StorageRequest struct {
	ContractAddress []byte `tl:"int256"`
	ByteToProof     uint64 `tl:"long"`
}

type StorageResponse struct {
	Status     string `tl:"string"`
	Reason     string `tl:"string"`
	Downloaded uint64 `tl:"long"`
	Proof      []byte `tl:"bytes"`
}

type StorageADNLProofRequest struct {
	ContractAddress []byte `tl:"int256"`
}

type StorageADNLProofResponse struct {
	StorageKey []byte `tl:"int256"`
	Signature  []byte `tl:"bytes"`
}

type ProviderDHTRecord struct {
	ADNLAddr []byte `tl:"int256"`
}

type ADNLProofScheme struct {
	Key []byte `tl:"int256"`
}
