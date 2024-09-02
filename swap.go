package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/gob"
	"maps"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
)

func (s *swapService) performSwap() error {
	if nodeIndex != 0 {
		return nil
	}
	for commit, onion := range s.onions {
		if _, err := validateOnion(onion); err != nil {
			delete(s.onions, commit)
		}
	}
	return s.forward()
}

func (s *swapService) peelOnions() map[*mw.Commitment]*onion.Onion {
	onions := map[*mw.Commitment]*onion.Onion{}
	for commit, onion := range s.onions {
		hop, onion, err := onion.Peel(serverKey)
		if err != nil {
			continue
		}
		commit = *commit.Add(mw.NewCommitment(&hop.KernelBlind, 0))
		commit = *commit.Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))
		onions[&commit] = onion
	}
	return onions
}

func (s *swapService) forward() error {
	onions := s.peelOnions()
	commits := slices.SortedFunc(maps.Keys(onions), func(c1, c2 *mw.Commitment) int {
		a := new(big.Int).SetBytes(c1[:])
		b := new(big.Int).SetBytes(c2[:])
		return a.Cmp(b)
	})

	if nodeIndex+1 < len(s.nodes) {
		node := s.nodes[nodeIndex+1]
		pubKey, err := ecdh.X25519().NewPublicKey([]byte(node.PubKey))
		if err != nil {
			return err
		}

		var data bytes.Buffer
		enc := gob.NewEncoder(&data)
		enc.Encode(len(commits))
		for _, commit := range commits {
			enc.Encode(commit)
			enc.Encode(onions[commit])
		}

		cipher := onion.NewCipher(serverKey, pubKey)
		cipher.XORKeyStream(data.Bytes(), data.Bytes())

		client, err := rpc.Dial(node.Url)
		if err != nil {
			return err
		}
		if err := client.Call(nil, "swap_forward", data.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func (s *swapService) Forward(data []byte) error {
	if nodeIndex == 0 {
		return nil
	}

	node := s.nodes[nodeIndex-1]
	pubKey, err := ecdh.X25519().NewPublicKey([]byte(node.PubKey))
	if err != nil {
		return err
	}

	cipher := onion.NewCipher(serverKey, pubKey)
	cipher.XORKeyStream(data, data)

	var (
		count  int
		commit *mw.Commitment
		onion  *onion.Onion
	)
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err = dec.Decode(&count); err != nil {
		return err
	}
	for ; count > 0; count-- {
		if err = dec.Decode(&commit); err != nil {
			return err
		}
		if err = dec.Decode(&onion); err != nil {
			return err
		}
		s.onions[*commit] = onion
	}

	return s.forward()
}
