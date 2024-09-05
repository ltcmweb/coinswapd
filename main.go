package main

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/config"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/chaincfg"
	"github.com/ltcmweb/ltcd/chaincfg/chainhash"
	"github.com/ltcmweb/ltcd/ltcutil"
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

	feeAddress     *mw.StealthAddress
	feeAddressFlag = flag.String("a", "", "MWEB address to collect fees to")

	forceSwap = flag.Bool("f", false, "Force-run a swap at startup")
)

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
	}()

	flag.Parse()
	serverKeyBytes, err := hex.DecodeString(*serverKeyFlag)
	if err != nil {
		return
	}
	serverKey, err = ecdh.X25519().NewPrivateKey(serverKeyBytes)
	if err != nil {
		return
	}
	nodes, err := getNodes()
	if err != nil {
		return
	}

	addr, err := ltcutil.DecodeAddress(*feeAddressFlag, &chaincfg.MainNetParams)
	if err != nil {
		return
	}
	feeAddress = addr.(*ltcutil.AddressMweb).StealthAddress()

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

	ss := &swapService{
		nodes:  nodes,
		onions: map[mw.Commitment]*onionEtc{},
	}

	onions, err := loadOnions(db)
	if err != nil {
		return
	}
	for _, onion := range onions {
		ss.addOnion(onion)
	}

	rpcServer := rpc.NewServer()
	rpcServer.RegisterName("swap", ss)
	http.HandleFunc("/", rpcServer.ServeHTTP)
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go httpServer.ListenAndServe()

	if *forceSwap {
		if err = ss.performSwap(); err != nil {
			return
		}
	}

	var (
		height, height2 uint32
		t, tPrev        time.Time
	)
	for ; ; t = <-time.After(2 * time.Second) {
		_, height2, err = cs.BlockHeaders.ChainTip()
		if err != nil {
			return
		}
		if height2 > height {
			fmt.Println("Syncing height", height2)
			height = height2
		}

		if !tPrev.IsZero() && tPrev.Hour() > t.Hour() {
			if err = ss.performSwap(); err != nil {
				return
			}
		}
		tPrev = t
	}
}

func getNodes() ([]config.Node, error) {
	pubKey := serverKey.PublicKey()
	fmt.Println("Public key =", hex.EncodeToString(pubKey.Bytes()))

	nodes := config.AliveNodes(context.Background(), pubKey)
	for i, node := range nodes {
		if node.PubKey().Equal(pubKey) {
			fmt.Println("Node", i+1, "of", len(nodes))
			nodeIndex = i
		}
	}
	if nodeIndex < 0 {
		return nil, errors.New("public key not found in config")
	}
	return nodes, nil
}

type swapService struct {
	mu       sync.Mutex
	nodes    []config.Node
	onions   map[mw.Commitment]*onionEtc
	outputs  []*wire.MwebOutput
	swapping bool
}

func (s *swapService) reset() (err error) {
	s.onions = map[mw.Commitment]*onionEtc{}
	s.outputs = nil
	s.swapping = false
	clearOnions(db)
	s.nodes, err = getNodes()
	return
}

func (s *swapService) Swap(onion onion.Onion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.swapping {
		return errors.New("swapping in progress")
	}
	if nodeIndex != 0 {
		return errors.New("node index is not zero")
	}
	if err := validateOnion(&onion); err != nil {
		return err
	}
	if err := saveOnion(db, &onion); err != nil {
		return err
	}
	s.addOnion(&onion)
	return nil
}

func (s *swapService) addOnion(onion *onion.Onion) {
	input, _ := inputFromOnion(onion)
	s.onions[input.Commitment] = &onionEtc{
		onion:      onion,
		stealthSum: input.OutputPubKey.Sub(input.InputPubKey),
	}
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

func validateOnion(onion *onion.Onion) error {
	input, err := inputFromOnion(onion)
	if err != nil {
		return err
	}

	output, err := cs.MwebCoinDB.FetchCoin(&input.OutputId)
	if err != nil {
		return err
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

	return nil
}
