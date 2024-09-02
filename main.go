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
	"github.com/ltcmweb/coinswapd/config"
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

	nodeIndex = -1

	port = flag.Int("l", 8080, "Listen port")
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
	pubKey := hex.EncodeToString(serverKey.PublicKey().Bytes())
	fmt.Println("Public key =", pubKey)

	nodes := config.AliveNodes(pubKey)
	for i, node := range nodes {
		if node.PubKey == pubKey {
			fmt.Println("Node", i+1, "of", len(nodes))
			nodeIndex = i
		}
	}
	if nodeIndex < 0 {
		fmt.Println("Public key not found in config")
		return
	}

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
	server.RegisterName("swap", &swapService{
		onions: map[mw.Commitment]*onion.Onion{},
	})
	http.HandleFunc("/", server.ServeHTTP)
	go http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)

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

type swapService struct {
	onions map[mw.Commitment]*onion.Onion
}

func (s *swapService) Swap(onion onion.Onion) error {
	commit, err := validateOnion(&onion)
	if err != nil {
		return err
	}
	s.onions[*commit] = &onion
	return nil
}

func (s *swapService) performSwap() error {
	onions := map[mw.Commitment]*onion.Onion{}

	for _, onion := range s.onions {
		commit, err := validateOnion(onion)
		if err != nil {
			continue
		}

		hop, _, err := onion.Peel(serverKey)
		if err != nil {
			continue
		}

		commit = commit.Add(mw.NewCommitment(&hop.KernelBlind, 0))
		commit = commit.Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))
		onions[*commit] = onion
	}

	s.onions = onions

	return nil
}

func inputFromOnion(onion *onion.Onion) (input *wire.MwebInput, err error) {
	defer func() { err, _ = recover().(error) }()
	return &wire.MwebInput{
		Features:     wire.MwebInputStealthKeyFeatureBit,
		OutputId:     chainhash.Hash(onion.Input.OutputId),
		Commitment:   mw.Commitment(onion.Input.Commitment),
		InputPubKey:  (*mw.PublicKey)(onion.Input.InputPubKey),
		OutputPubKey: mw.PublicKey(onion.Input.OutputPubKey),
		Signature:    mw.Signature(onion.Input.Signature),
	}, nil
}

func validateOnion(onion *onion.Onion) (*mw.Commitment, error) {
	input, err := inputFromOnion(onion)
	if err != nil {
		return nil, err
	}

	output, err := cs.MwebCoinDB.FetchCoin(&input.OutputId)
	if err != nil {
		return nil, err
	}

	if input.Commitment != output.Commitment {
		return nil, errors.New("commitment mismatch")
	}
	if input.OutputPubKey != output.ReceiverPubKey {
		return nil, errors.New("output pubkey mismatch")
	}

	if !input.VerifySig() {
		return nil, errors.New("verify input sig failed")
	}
	if !onion.VerifySig() {
		return nil, errors.New("verify onion sig failed")
	}

	return &input.Commitment, nil
}
