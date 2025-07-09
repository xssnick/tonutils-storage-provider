.PHONY: all build

ver := $(shell git describe --tags --always --dirty)

build:
	go build -ldflags "-X main.GitCommit=$(ver)" -o build/tonutils-storage-provider cmd/main.go

all:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.GitCommit=$(ver)" -o build/tonutils-storage-provider-linux-amd64 cmd/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.GitCommit=$(ver)" -o build/tonutils-storage-provider-linux-arm64 cmd/main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.GitCommit=$(ver)" -o build/tonutils-storage-provider-mac-arm64 cmd/main.go
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.GitCommit=$(ver)" -o build/tonutils-storage-provider-mac-amd64 cmd/main.go
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.GitCommit=$(ver)" -o build/tonutils-storage-provider-x64.exe cmd/main.go