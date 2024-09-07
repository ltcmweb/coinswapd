package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/openpgp"
)

var signers = map[string]string{
	"coblee":         "1a2511e978239e491a096d0a828ac1f94ef26053",
	"davidburkett38": "d35621d53a1cc6a3456758d03620e9d387e55666",
	"hectorchu":      "7fe6094dcb3a76262ee4c6896ec371a844f2c48e",
	"losh11":         "c0921846fed0bf4cf28be1d73b2a6315cd51a673",
	"theholyroger":   "9d87563f0826753f280c69c24c8240100c3d5acd",
	"ultragtx":       "786da2e86e27cd6e4b764accc31f0c372190277e",
}

var signerKeys = map[string]openpgp.KeyRing{}

func fetchPgpKey(signer string) (openpgp.KeyRing, error) {
	if signerKeys[signer] != nil {
		return signerKeys[signer], nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://raw.githubusercontent.com/DavidBurkett" +
		"/ltc-release-builder/master/gitian-keys/" + signer + "-key.pgp")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	key, err := openpgp.ReadArmoredKeyRing(resp.Body)
	if err != nil {
		return nil, err
	}
	if signers[signer] != hex.EncodeToString(key[0].PrimaryKey.Fingerprint[:]) {
		return nil, errors.New("wrong fingerprint")
	}
	signerKeys[signer] = key
	return key, nil
}

func verifyPgpSig(signed, signature io.Reader) (string, bool) {
	sig, err := io.ReadAll(signature)
	if err != nil {
		return "", false
	}
	for signer := range signers {
		key, err := fetchPgpKey(signer)
		if err != nil {
			continue
		}
		_, err = openpgp.CheckDetachedSignature(key, signed, bytes.NewReader(sig))
		if err == nil {
			return signer, true
		}
	}
	return "", false
}
