package onion

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ltcmweb/ltcd/ltcutil/mweb/mw"
	"github.com/ltcmweb/ltcd/wire"
	"golang.org/x/crypto/chacha20"
	"lukechampine.com/blake3"
)

type (
	Hop struct {
		PubKey       *ecdh.PublicKey
		KernelBlind  mw.BlindingFactor
		StealthBlind mw.BlindingFactor
		Fee          uint64
		Output       *wire.MwebOutput
	}
	Onion struct {
		Input struct {
			OutputId     hexBytes `json:"output_id"`
			Commitment   hexBytes `json:"output_commit"`
			OutputPubKey hexBytes `json:"output_pk"`
			InputPubKey  hexBytes `json:"input_pk"`
			Signature    hexBytes `json:"input_sig"`
		} `json:"input"`
		Payloads   hexBytes `json:"enc_payloads"`
		PubKey     hexBytes `json:"ephemeral_xpub"`
		OwnerProof hexBytes `json:"owner_proof"`
	}
	hexBytes []byte
)

func (h hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *hexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return
	}
	*h, err = hex.DecodeString(s)
	return
}

func New(hops []*Hop) (*Onion, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	onion := &Onion{PubKey: privKey.PublicKey().Bytes()}

	var (
		ciphers  []*chacha20.Cipher
		payloads [][]byte
	)
	for i, hop := range hops {
		ciphers = append(ciphers, NewCipher(privKey, hop.PubKey))

		privKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		buf.WriteByte(0)
		if i < len(hops)-1 {
			buf.Write(privKey.PublicKey().Bytes())
		} else {
			buf.Write(make([]byte, 32))
		}

		buf.Write(hop.KernelBlind[:])
		buf.Write(hop.StealthBlind[:])
		binary.Write(&buf, binary.BigEndian, hop.Fee)

		if hop.Output != nil {
			buf.WriteByte(1)
			hop.Output.Serialize(&buf)
		} else {
			buf.WriteByte(0)
		}

		payloads = append(payloads, buf.Bytes())
	}

	for i := len(payloads) - 1; i >= 0; i-- {
		for j := i; j < len(payloads); j++ {
			ciphers[i].XORKeyStream(payloads[j], payloads[j])
		}
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint64(len(payloads)))
	for _, payload := range payloads {
		binary.Write(&buf, binary.BigEndian, uint64(len(payload)))
		buf.Write(payload)
	}
	onion.Payloads = buf.Bytes()
	return onion, nil
}

func NewCipher(privKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey) *chacha20.Cipher {
	secret, _ := privKey.ECDH(pubKey)
	h := hmac.New(sha256.New, []byte("MWIXNET"))
	h.Write(secret)
	cipher, _ := chacha20.NewUnauthenticatedCipher(h.Sum(nil), []byte("NONCE1234567"))
	return cipher
}

func (onion *Onion) Sign(input *wire.MwebInput, spendKey *mw.SecretKey) {
	onion.Input.OutputId = input.OutputId[:]
	onion.Input.Commitment = input.Commitment[:]
	onion.Input.OutputPubKey = input.OutputPubKey[:]
	onion.Input.InputPubKey = input.InputPubKey[:]
	onion.Input.Signature = input.Signature[:]

	h := blake3.New(32, nil)
	h.Write(input.InputPubKey[:])
	h.Write(input.OutputPubKey[:])
	keyHash := (*mw.SecretKey)(h.Sum(nil))

	sig := mw.Sign(spendKey.Mul(keyHash), onion.sigMsg())
	onion.OwnerProof = sig[:]
}

func (onion *Onion) sigMsg() []byte {
	var buf bytes.Buffer
	buf.Write(onion.Input.OutputId)
	buf.Write(onion.Input.Commitment)
	buf.Write(onion.Input.OutputPubKey)
	buf.Write(onion.Input.InputPubKey)
	buf.Write(onion.Input.Signature)
	buf.Write(onion.Payloads)
	buf.Write(onion.PubKey)
	return buf.Bytes()
}

func (onion *Onion) VerifySig() bool {
	defer func() { recover() }()

	h := blake3.New(32, nil)
	h.Write(onion.Input.InputPubKey)
	h.Write(onion.Input.OutputPubKey)
	keyHash := (*mw.SecretKey)(h.Sum(nil))

	sig := (*mw.Signature)(onion.OwnerProof)
	outputPubKey := (*mw.PublicKey)(onion.Input.OutputPubKey)
	return sig.Verify(outputPubKey.Mul(keyHash), onion.sigMsg())
}

func (onion *Onion) Peel(privKey *ecdh.PrivateKey) (*Hop, *Onion, error) {
	pubKey, err := ecdh.X25519().NewPublicKey(onion.PubKey)
	if err != nil {
		return nil, nil, err
	}
	cipher := NewCipher(privKey, pubKey)

	var (
		count, size uint64
		payload     []byte
		payloads    bytes.Buffer
	)
	r := bytes.NewReader(onion.Payloads)
	if err = binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, nil, err
	}
	binary.Write(&payloads, binary.BigEndian, count-1)
	for i := uint64(0); i < count; i++ {
		if err = binary.Read(r, binary.BigEndian, &size); err != nil {
			return nil, nil, err
		}
		buf := make([]byte, size)
		if _, err = r.Read(buf); err != nil {
			return nil, nil, err
		}
		cipher.XORKeyStream(buf, buf)
		if i == 0 {
			payload = buf
		} else {
			binary.Write(&payloads, binary.BigEndian, size)
			payloads.Write(buf)
		}
	}

	r = bytes.NewReader(payload)
	ver, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	if ver != 0 {
		return nil, nil, errors.New("wrong onion version")
	}

	onion = &Onion{
		Payloads: payloads.Bytes(),
		PubKey:   make([]byte, 32),
	}
	if _, err = r.Read(onion.PubKey); err != nil {
		return nil, nil, err
	}

	hop := &Hop{}
	if _, err = r.Read(hop.KernelBlind[:]); err != nil {
		return nil, nil, err
	}
	if _, err = r.Read(hop.StealthBlind[:]); err != nil {
		return nil, nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &hop.Fee); err != nil {
		return nil, nil, err
	}

	hasOutput, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	if hasOutput == 1 {
		hop.Output = &wire.MwebOutput{}
		if err = hop.Output.Deserialize(r); err != nil {
			return nil, nil, err
		}
	}

	return hop, onion, nil
}
