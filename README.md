# Tonutils Storage Provider

Written in pure go, can be compiled for any OS.

1. Build with `go build cmd/main.go` and start it `./tonutils-storage-provider`, it will generate config.json
2. Topup provider wallet, address will be shown in output at startup
3. Run dev version of [tonutils-storage](https://github.com/xssnick/tonutils-storage) from `provider` branch with api enabled `-api ip:port` flag
4. Configure settings such as tountils-storage api address, space for rent and price in config.json
5. Share provider key with your clients, it will be shown in output at startup also. Clients can use it in TON Torrent to buy your storage.
