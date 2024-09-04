package main

import (
	"bytes"
	"encoding/gob"

	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcsuite/ltcwallet/walletdb"
)

var coinswapOnionsBucket = []byte("coinswap-onions")

func saveOnion(db walletdb.DB, onion *onion.Onion) error {
	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		bucket, err := tx.CreateTopLevelBucket(coinswapOnionsBucket)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		enc.Encode(onion)
		return bucket.Put(onion.Input.Commitment, buf.Bytes())
	})
}

func loadOnions(db walletdb.DB) (onions []*onion.Onion, err error) {
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		bucket := tx.ReadBucket(coinswapOnionsBucket)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var onion *onion.Onion
			dec := gob.NewDecoder(bytes.NewReader(v))
			err = dec.Decode(&onion)
			onions = append(onions, onion)
			return err
		})
	})
	return
}

func clearOnions(db walletdb.DB) error {
	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		tx.DeleteTopLevelBucket(coinswapOnionsBucket)
		return nil
	})
}
