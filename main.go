package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/neutrino"
	"github.com/ltcsuite/ltcwallet/walletdb"
	_ "github.com/ltcsuite/ltcwallet/walletdb/bdb"
)

var (
	db walletdb.DB
	cs *neutrino.ChainService
)

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
	}()

	db, err = walletdb.Create("bdb", "neutrino.db", true, time.Minute)
	if err != nil {
		return
	}

	cs, err = neutrino.NewChainService(neutrino.Config{
		Database:    db,
		ChainParams: chaincfg.MainNetParams,
	})
	if err != nil {
		return
	}

	if err = cs.Start(); err != nil {
		return
	}

	server := rpc.NewServer()
	server.RegisterName("rpc", &swapService{})
	http.HandleFunc("/", server.ServeHTTP)
	go http.ListenAndServe(":8080", nil)

	for height := uint32(0); ; <-time.After(2 * time.Second) {
		_, height2, err := cs.BlockHeaders.ChainTip()
		if err != nil {
			return
		}
		if height2 > height {
			fmt.Println("Syncing height", height2)
			height = height2
		}
	}
}

type swapService struct{}

func (s *swapService) Swap(onion *onion.Onion) error {
	return nil
}
