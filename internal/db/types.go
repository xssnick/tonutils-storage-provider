package db

import "errors"

type StoredBagStatus int
type StoredBag struct {
	BagID        []byte          `json:"b"`
	Size         uint64          `json:"s"`
	ContractAddr string          `json:"a"`
	Status       StoredBagStatus `json:"t"`
}

var ErrNotFound = errors.New("not found")

const (
	StoredBagStatusAdded StoredBagStatus = iota
	StoredBagStatusActive
	StoredBagStatusStopped
)
