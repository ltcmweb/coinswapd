package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"maps"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
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

func (s *swapService) peelOnions() map[mw.Commitment]*onion.Onion {
	onions := map[mw.Commitment]*onion.Onion{}

	for commit, onion := range s.onions {
		hop, onion, err := onion.Peel(serverKey)
		if err != nil {
			delete(s.onions, commit)
			continue
		}

		commit2 := commit.Add(mw.NewCommitment(&hop.KernelBlind, 0)).
			Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))

		if _, ok := onions[*commit2]; ok {
			delete(s.onions, commit)
			continue
		}

		lastNode := nodeIndex == len(s.nodes)-1
		hasOutput := hop.Output != nil

		if lastNode != hasOutput {
			delete(s.onions, commit)
			continue
		}

		if hasOutput {
			var msg bytes.Buffer
			hop.Output.Message.Serialize(&msg)

			if *commit2 != hop.Output.Commitment ||
				hop.Output.RangeProof == nil ||
				!hop.Output.RangeProof.Verify(*commit2, msg.Bytes()) ||
				!hop.Output.VerifySig() {

				delete(s.onions, commit)
				continue
			}

			s.outputs = append(s.outputs, hop.Output)
		}

		onions[*commit2] = onion
	}

	return onions
}

func (s *swapService) forward() error {
	onions := s.peelOnions()

	if nodeIndex == len(s.nodes)-1 {
		return s.backward(nil)
	}

	commits := slices.SortedFunc(maps.Keys(onions), func(c1, c2 mw.Commitment) int {
		a := new(big.Int).SetBytes(c1[:])
		b := new(big.Int).SetBytes(c2[:])
		return a.Cmp(b)
	})

	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	enc.Encode(commits)
	for _, commit := range commits {
		enc.Encode(onions[commit])
	}

	node := s.nodes[nodeIndex+1]
	pubKey, err := ecdh.X25519().NewPublicKey([]byte(node.PubKey))
	if err != nil {
		return err
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
		commits []mw.Commitment
		onion   *onion.Onion
	)
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err = dec.Decode(&commits); err != nil {
		return err
	}
	for _, commit := range commits {
		if err = dec.Decode(&onion); err != nil {
			return err
		}
		s.onions[commit] = onion
	}

	return s.forward()
}

func (s *swapService) backward(kernels []*wire.MwebKernel) error {
	var (
		kernelBlind  mw.BlindingFactor
		stealthBlind mw.BlindingFactor
		senderKey    mw.SecretKey
		nodeFee      uint64
	)

	for _, onion := range s.onions {
		hop, _, _ := onion.Peel(serverKey)
		kernelBlind = *kernelBlind.Add(&hop.KernelBlind)
		stealthBlind = *stealthBlind.Add(&hop.StealthBlind)
		nodeFee += hop.Fee
	}

	nOutputs := len(s.outputs) + nodeIndex + 1
	nNodes := uint64(len(s.nodes))
	fee := uint64(nOutputs) * mweb.StandardOutputWeight * mweb.BaseMwebFee
	fee = (fee + nNodes - 1) / nNodes
	fee += mweb.KernelWithStealthWeight * mweb.BaseMwebFee

	if nodeFee < fee {
		return errors.New("insufficient hop fees")
	}
	nodeFee -= fee

	if _, err := rand.Read(senderKey[:]); err != nil {
		return err
	}
	output, blind, _ := mweb.CreateOutput(&mweb.Recipient{
		Value: nodeFee, Address: feeAddress}, &senderKey)
	kernelBlind = *kernelBlind.Add(mw.BlindSwitch(blind, nodeFee))
	stealthBlind = *stealthBlind.Add((*mw.BlindingFactor)(&senderKey))
	s.outputs = append(s.outputs, output)

	kernels = append(kernels, mweb.CreateKernel(
		&kernelBlind, &stealthBlind, &fee, nil, nil, nil))

	slices.SortFunc(s.outputs, func(o1, o2 *wire.MwebOutput) int {
		a := new(big.Int).SetBytes(o1.Hash()[:])
		b := new(big.Int).SetBytes(o2.Hash()[:])
		return a.Cmp(b)
	})

	if nodeIndex == 0 {
		return s.finalize(kernels)
	}

	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	enc.Encode(slices.Collect(maps.Keys(s.onions)))
	enc.Encode(len(s.outputs))
	for _, output := range s.outputs {
		output.Serialize(&data)
	}
	for _, kernel := range kernels {
		kernel.Serialize(&data)
	}

	node := s.nodes[nodeIndex-1]
	pubKey, err := ecdh.X25519().NewPublicKey([]byte(node.PubKey))
	if err != nil {
		return err
	}

	cipher := onion.NewCipher(serverKey, pubKey)
	cipher.XORKeyStream(data.Bytes(), data.Bytes())

	client, err := rpc.Dial(node.Url)
	if err != nil {
		return err
	}
	if err := client.Call(nil, "swap_backward", data.Bytes()); err != nil {
		return err
	}

	return nil
}

func (s *swapService) Backward(data []byte) error {
	if nodeIndex == len(s.nodes)-1 {
		return nil
	}

	node := s.nodes[nodeIndex+1]
	pubKey, err := ecdh.X25519().NewPublicKey([]byte(node.PubKey))
	if err != nil {
		return err
	}

	cipher := onion.NewCipher(serverKey, pubKey)
	cipher.XORKeyStream(data, data)

	var (
		r         = bytes.NewReader(data)
		dec       = gob.NewDecoder(r)
		count     int
		commits   []mw.Commitment
		kernels   []*wire.MwebKernel
		commitSum mw.Commitment
		kernelSum mw.Commitment
	)

	if err = dec.Decode(&commits); err != nil {
		return err
	}
	if err = dec.Decode(&count); err != nil {
		return err
	}

	for ; count > 0; count-- {
		output := &wire.MwebOutput{}
		if err = output.Deserialize(r); err != nil {
			return err
		}
		s.outputs = append(s.outputs, output)
		commitSum = *commitSum.Add(&output.Commitment)
	}

	for i := nodeIndex + 1; i < len(s.nodes); i++ {
		kernel := &wire.MwebKernel{}
		if err = kernel.Deserialize(r); err != nil {
			return err
		}
		kernels = append(kernels, kernel)
		kernelSum = *kernelSum.Add(&kernel.Excess).
			Sub(mw.NewCommitment(&mw.BlindingFactor{}, kernel.Fee))
	}

	for commit, onion := range s.onions {
		hop, _, _ := onion.Peel(serverKey)

		commit2 := commit.Add(mw.NewCommitment(&hop.KernelBlind, 0)).
			Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))

		if slices.Contains(commits, *commit2) {
			commitSum = *commitSum.Sub(commit2)
		} else {
			delete(s.onions, commit)
		}
	}

	if commitSum != kernelSum {
		return errors.New("commit invariant not satisfied")
	}

	return s.backward(kernels)
}

func (s *swapService) finalize(kernels []*wire.MwebKernel) error {
	txBody := &wire.MwebTxBody{
		Outputs: s.outputs,
		Kernels: kernels,
	}
	for _, onion := range s.onions {
		input, _ := inputFromOnion(onion)
		txBody.Inputs = append(txBody.Inputs, input)
	}
	txBody.Sort()
	return cs.SendTransaction(&wire.MsgTx{
		Version: 2,
		Mweb:    &wire.MwebTx{TxBody: txBody},
	})
}
