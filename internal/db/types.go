package db

import "errors"

type StoredBagStatus int
type StoredBag struct {
	BagID        []byte          `json:"b"`
	Size         uint64          `json:"s"`
	ContractAddr string          `json:"a"`
	Status       StoredBagStatus `json:"t"`
}

type CronContract struct {
	ContractAddr string `json:"a"`
	NextQuery    int64  `json:"t"`
	Reward       string `json:"r"`
}

var ErrNotFound = errors.New("not found")

const (
	StoredBagStatusAdded StoredBagStatus = iota
	StoredBagStatusActive
	StoredBagStatusStopped
)
