package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/neutrino"
	"github.com/ltcsuite/ltcwallet/walletdb"
	_ "github.com/ltcsuite/ltcwallet/walletdb/bdb"
)

var (
	db walletdb.DB
	cs *neutrino.ChainService

	serverKey     *ecdh.PrivateKey
	serverKeyFlag = flag.String("k", "", "ECDH private key")
)

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
	}()

	flag.Parse()
	serverKey, err = ecdh.X25519().NewPrivateKey([]byte(*serverKeyFlag))
	if err != nil {
		return
	}
	fmt.Println("Public key =", hex.EncodeToString(serverKey.PublicKey().Bytes()))

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
	server.RegisterName("swap", &swapService{})
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

func (s *swapService) Swap(onion onion.Onion) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case string:
				err = errors.New(r)
			case error:
				err = r
			}
		}
	}()
	input := &wire.MwebInput{
		Features:     wire.MwebInputStealthKeyFeatureBit,
		OutputId:     chainhash.Hash(onion.Input.OutputId),
		Commitment:   mw.Commitment(onion.Input.Commitment),
		InputPubKey:  (*mw.PublicKey)(onion.Input.InputPubKey),
		OutputPubKey: mw.PublicKey(onion.Input.OutputPubKey),
		Signature:    mw.Signature(onion.Input.Signature),
	}
	output, err := cs.MwebCoinDB.FetchCoin(&input.OutputId)
	if err != nil {
		return
	}
	if input.Commitment != output.Commitment {
		return errors.New("commitment mismatch")
	}
	if input.OutputPubKey != output.ReceiverPubKey {
		return errors.New("output pubkey mismatch")
	}
	if !input.VerifySig() {
		return errors.New("verify input sig failed")
	}
	if !onion.VerifySig() {
		return errors.New("verify onion sig failed")
	}
	hop, onion2, err := onion.Peel(serverKey)
	if err != nil {
		return
	}
	fmt.Println(hop, onion2)
	return
}
