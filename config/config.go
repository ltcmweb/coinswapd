package config

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

func (node Node) PubKey() *ecdh.PublicKey {
	bs, err := hex.DecodeString(node.pubKey)
	if err != nil {
		panic(err)
	}
	pubKey, err := ecdh.X25519().NewPublicKey(bs)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func AliveNodes(ctx context.Context, pubKey *ecdh.PublicKey) (nodes []Node) {
	for _, node := range Nodes {
		if pubKey != nil && node.PubKey().Equal(pubKey) {
			nodes = append(nodes, node)
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, node.Url, nil)
		fmt.Print("Checking node ", node.Url, "...")
		if resp, err := http.DefaultClient.Do(req); err == nil && resp.StatusCode == 200 {
			nodes = append(nodes, node)
			fmt.Println(" ok")
		} else {
			fmt.Println(" not ok")
		}
		cancel()
	}
	return
}
