package leveldb

import (
	"encoding/json"
	"errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/xssnick/tonutils-storage-provider/internal/db"
)

type DB struct {
	db *leveldb.DB
}

func NewDB(path string) (*DB, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}

	return &DB{
		db: db,
	}, nil
}

func (d *DB) SetContract(bag db.StoredBag) error {
	data, err := json.Marshal(bag)
	if err != nil {
		return err
	}

	if err = d.db.Put([]byte("c:"+bag.ContractAddr), data, nil); err != nil {
		return err
	}
	return nil
}

func (d *DB) GetContract(addr string) (db.StoredBag, error) {
	data, err := d.db.Get([]byte("c:"+addr), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			err = db.ErrNotFound
		}
		return db.StoredBag{}, err
	}

	var bag db.StoredBag
	if err = json.Unmarshal(data, &bag); err != nil {
		return db.StoredBag{}, err
	}
	return bag, nil
}

func (d *DB) ListContracts() ([]db.StoredBag, error) {
	it := d.db.NewIterator(util.BytesPrefix([]byte("c:")), nil)
	defer it.Release()

	var bags []db.StoredBag
	for it.Next() {
		var bag db.StoredBag
		if err := json.Unmarshal(it.Value(), &bag); err != nil {
			continue
		}
		bags = append(bags, bag)
	}
	return bags, nil
}
