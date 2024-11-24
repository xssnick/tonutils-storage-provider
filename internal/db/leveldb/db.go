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
	d, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}

	return &DB{
		db: d,
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

func (d *DB) ListCronContracts() ([]db.CronContract, error) {
	it := d.db.NewIterator(util.BytesPrefix([]byte("n:")), nil)
	defer it.Release()

	var contracts []db.CronContract
	for it.Next() {
		var crn db.CronContract
		if err := json.Unmarshal(it.Value(), &crn); err != nil {
			continue
		}
		contracts = append(contracts, crn)
	}
	return contracts, nil
}

func (d *DB) SetCronContract(crn db.CronContract) error {
	data, err := json.Marshal(crn)
	if err != nil {
		return err
	}

	if err = d.db.Put([]byte("n:1:"+crn.ContractAddr), data, nil); err != nil {
		return err
	}
	return nil
}

func (d *DB) DeleteCronContract(addr string) error {
	err := d.db.Delete([]byte("n:1:"+addr), nil)
	if err != nil {
		return err
	}
	return nil
}

func (d *DB) GetCronScannerLT() (uint64, error) {
	data, err := d.db.Get([]byte("cron_scanner_lt"), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return 0, db.ErrNotFound
		}
		return 0, err
	}
	var lt uint64
	if err := json.Unmarshal(data, &lt); err != nil {
		return 0, err
	}
	return lt, nil
}

func (d *DB) SetCronScannerLT(lt uint64) error {
	data, err := json.Marshal(lt)
	if err != nil {
		return err
	}
	if err = d.db.Put([]byte("cron_scanner_lt"), data, nil); err != nil {
		return err
	}
	return nil
}
