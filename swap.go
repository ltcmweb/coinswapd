package main

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ltcmweb/coinswapd/onion"
	"github.com/ltcmweb/ltcd/ltcutil/mweb"
	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
)

type onionEtc struct {
	Onion      *onion.Onion
	StealthSum *mw.PublicKey
}

func (s *swapService) performSwap() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.nodeIndex != 0 {
		return nil
	}
	fmt.Println("Performing swap")

	onions, err := loadOnions(db)
	if err != nil {
		return err
	}

	s.onions = map[mw.Commitment]*onionEtc{}
	for _, onion := range onions {
		if err = validateOnion(onion); err != nil {
			if err = deleteOnion(db, onion); err != nil {
				return err
			}
			continue
		}

		input, _ := inputFromOnion(onion)
		s.onions[input.Commitment] = &onionEtc{
			Onion:      onion,
			StealthSum: input.OutputPubKey.Sub(input.InputPubKey),
		}
	}

	return s.forward()
}

func (s *swapService) peelOnions() (
	onions map[mw.Commitment]*onionEtc,
	outputs []*wire.MwebOutput) {

	onions = map[mw.Commitment]*onionEtc{}

	for commit, o := range s.onions {
		hop, onion, err := o.Onion.Peel(serverKey)
		if err != nil {
			delete(s.onions, commit)
			continue
		}

		commit2 := commit.Add(mw.NewCommitment(&hop.KernelBlind, 0)).
			Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))

		stealthBlind := mw.SecretKey(hop.StealthBlind)
		stealthSum := o.StealthSum.Add(stealthBlind.PubKey())

		if _, ok := onions[*commit2]; ok {
			delete(s.onions, commit)
			continue
		}

		lastNode := s.nodeIndex == len(s.nodes)-1
		hasOutput := hop.Output != nil

		if lastNode != hasOutput {
			delete(s.onions, commit)
			continue
		}

		if hasOutput {
			var msg bytes.Buffer
			hop.Output.Message.Serialize(&msg)

			if *commit2 != hop.Output.Commitment ||
				*stealthSum != hop.Output.SenderPubKey ||
				hop.Output.RangeProof == nil ||
				!hop.Output.RangeProof.Verify(*commit2, msg.Bytes()) ||
				!hop.Output.VerifySig() {

				delete(s.onions, commit)
				continue
			}

			outputs = append(outputs, hop.Output)
		}

		onions[*commit2] = &onionEtc{onion, stealthSum}
	}

	return
}

func (s *swapService) forward() error {
	onions, outputs := s.peelOnions()

	if s.nodeIndex == len(s.nodes)-1 {
		return s.backward(outputs, nil)
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

	node := s.nodes[s.nodeIndex+1]
	cipher := onion.NewCipher(serverKey, node.PubKey())
	cipher.XORKeyStream(data.Bytes(), data.Bytes())

	client, err := rpc.Dial(node.Url)
	if err != nil {
		return err
	}

	go func() {
		err := client.Call(nil, "swap_forward", data.Bytes())
		if err != nil {
			fmt.Println("swap_forward:", err)
		}
	}()

	return nil
}

func (s *swapService) Forward(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.nodeIndex == 0 {
		return nil
	}

	node := s.nodes[s.nodeIndex-1]
	cipher := onion.NewCipher(serverKey, node.PubKey())
	cipher.XORKeyStream(data, data)

	var (
		commits []mw.Commitment
		onion   *onionEtc
	)

	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&commits); err != nil {
		return err
	}

	s.onions = map[mw.Commitment]*onionEtc{}
	for _, commit := range commits {
		if err := dec.Decode(&onion); err != nil {
			return err
		}
		s.onions[commit] = onion
	}

	return s.forward()
}

func (s *swapService) backward(
	outputs []*wire.MwebOutput,
	kernels []*wire.MwebKernel) error {

	var (
		kernelBlind  mw.BlindingFactor
		stealthBlind mw.BlindingFactor
		senderKey    mw.SecretKey
		nodeFee      uint64
	)

	for _, o := range s.onions {
		hop, _, _ := o.Onion.Peel(serverKey)
		kernelBlind = *kernelBlind.Add(&hop.KernelBlind)
		stealthBlind = *stealthBlind.Add(&hop.StealthBlind)
		nodeFee += hop.Fee
	}

	nOutputs := len(outputs) + s.nodeIndex + 1
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
	outputs = append(outputs, output)

	kernels = append(kernels, mweb.CreateKernel(
		&kernelBlind, &stealthBlind, &fee, nil, nil, nil))

	slices.SortFunc(outputs, func(o1, o2 *wire.MwebOutput) int {
		a := new(big.Int).SetBytes(o1.Hash()[:])
		b := new(big.Int).SetBytes(o2.Hash()[:])
		return a.Cmp(b)
	})

	if s.nodeIndex == 0 {
		return s.finalize(outputs, kernels)
	}

	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	enc.Encode(slices.Collect(maps.Keys(s.onions)))
	enc.Encode(len(outputs))
	for _, output := range outputs {
		output.Serialize(&data)
	}
	for _, kernel := range kernels {
		kernel.Serialize(&data)
	}

	node := s.nodes[s.nodeIndex-1]
	cipher := onion.NewCipher(serverKey, node.PubKey())
	cipher.XORKeyStream(data.Bytes(), data.Bytes())

	client, err := rpc.Dial(node.Url)
	if err != nil {
		return err
	}

	go func() {
		err := client.Call(nil, "swap_backward", data.Bytes())
		if err != nil {
			fmt.Println("swap_backward:", err)
		}
	}()

	return nil
}

func (s *swapService) Backward(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.nodeIndex == len(s.nodes)-1 {
		return nil
	}

	node := s.nodes[s.nodeIndex+1]
	cipher := onion.NewCipher(serverKey, node.PubKey())
	cipher.XORKeyStream(data, data)

	var (
		r       = bytes.NewReader(data)
		dec     = gob.NewDecoder(r)
		count   int
		commits []mw.Commitment
		outputs []*wire.MwebOutput
		kernels []*wire.MwebKernel

		commitSum, kernelExcess   mw.Commitment
		stealthSum, stealthExcess mw.PublicKey
	)

	if err := dec.Decode(&commits); err != nil {
		return err
	}
	if err := dec.Decode(&count); err != nil {
		return err
	}

	for ; count > 0; count-- {
		output := &wire.MwebOutput{}
		if err := output.Deserialize(r); err != nil {
			return err
		}
		outputs = append(outputs, output)
		commitSum = *commitSum.Add(&output.Commitment)
		stealthSum = *stealthSum.Add(&output.SenderPubKey)
	}

	for i := s.nodeIndex + 1; i < len(s.nodes); i++ {
		kernel := &wire.MwebKernel{}
		if err := kernel.Deserialize(r); err != nil {
			return err
		}
		kernels = append(kernels, kernel)
		kernelExcess = *kernelExcess.Add(&kernel.Excess).
			Sub(mw.NewCommitment(&mw.BlindingFactor{}, kernel.Fee))
		stealthExcess = *stealthExcess.Add(&kernel.StealthExcess)
	}

	for commit, o := range s.onions {
		hop, _, _ := o.Onion.Peel(serverKey)

		commit2 := commit.Add(mw.NewCommitment(&hop.KernelBlind, 0)).
			Sub(mw.NewCommitment(&mw.BlindingFactor{}, hop.Fee))

		if slices.Contains(commits, *commit2) {
			commitSum = *commitSum.Sub(commit2)
			stealthBlind := mw.SecretKey(hop.StealthBlind)
			stealthSum = *stealthSum.Sub(o.StealthSum.Add(stealthBlind.PubKey()))
		} else {
			delete(s.onions, commit)
		}
	}

	if commitSum != kernelExcess {
		return errors.New("commit invariant not satisfied")
	}
	if stealthSum != stealthExcess {
		return errors.New("stealth invariant not satisfied")
	}

	return s.backward(outputs, kernels)
}

func (s *swapService) finalize(
	outputs []*wire.MwebOutput,
	kernels []*wire.MwebKernel) error {

	txBody := &wire.MwebTxBody{
		Outputs: outputs,
		Kernels: kernels,
	}
	for _, o := range s.onions {
		input, _ := inputFromOnion(o.Onion)
		txBody.Inputs = append(txBody.Inputs, input)
	}
	txBody.Sort()

	return cs.SendTransaction(&wire.MsgTx{
		Version: 2,
		Mweb:    &wire.MwebTx{TxBody: txBody},
	})
}
