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
	bs, _ := hex.DecodeString(node.pubKey)
	pubKey, _ := ecdh.X25519().NewPublicKey(bs)
	return pubKey
}

func AliveNodes(ctx context.Context, pubKey *ecdh.PublicKey) (nodes []Node, index int) {
	index = -1
	fetchRemoteNodes()
	for _, node := range Nodes {
		if pubKey != nil && node.PubKey().Equal(pubKey) {
			index = len(nodes)
			nodes = append(nodes, node)
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, node.Url, nil)
		fmt.Print("Checking node ", node.Url, "...")
		if resp, err := http.DefaultClient.Do(req); err == nil && resp.StatusCode == http.StatusOK {
			nodes = append(nodes, node)
			fmt.Println(" ok")
		} else {
			fmt.Println(" not ok")
		}
		cancel()
	}
	return
}
