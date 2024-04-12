# Tonutils Storage Provider

Written in pure go, can be compiled for any OS.

It uses alternative version of storage contract and different flow, so it is not compatible with C++ storage-provider.

### How to setup

1. Download precompiled version:
   * [Linux AMD64](https://github.com/xssnick/tonutils-storage-provider/releases/download/v0.2.0/tonutils-storage-provider-linux-amd64)
   * [Linux ARM64](https://github.com/xssnick/tonutils-storage-provider/releases/download/v0.2.0/tonutils-storage-provider-linux-arm64)
   * [Windows x64](https://github.com/xssnick/tonutils-storage-provider/releases/download/v0.2.0/tonutils-storage-provider-x64.exe)
   * [Mac Intel](https://github.com/xssnick/tonutils-storage-provider/releases/download/v0.2.0/tonutils-storage-provider-mac-amd64)
   * [Mac Apple Silicon](https://github.com/xssnick/tonutils-storage-provider/releases/download/v0.2.0/tonutils-storage-provider-mac-arm64)
   * Or compile using `go build -o tonutils-storage-provider cmd/main.go`
2. Start it `./tonutils-storage-provider-{os}-{arch}`, it will generate config.json
3. Topup provider wallet, address will be shown in output at startup
4. Run [tonutils-storage](https://github.com/xssnick/tonutils-storage) version v0.4.0 or later, **with api enabled** `-api ip:port` flag
5. Configure settings such as tountils-storage api address, space for rent and price in config.json
6. Share provider key with your clients, it will be shown in output at startup also. Clients can use it in TON Torrent to buy your storage.

### Storage smart-contract

Contract used for providing storage is shared between many providers and can be deployed by user asking for storage. Contract is discoverable onchain if owner address and bag info is known. 

Contract source can be found [here](https://github.com/xssnick/tonutils-contracts/blob/master/contracts/storage/storage-contract.fc)
