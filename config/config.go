package config

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func AliveNodes(ctx context.Context, pubKey string) (nodes []Node) {
	for _, node := range Nodes {
		if node.PubKey == pubKey {
			nodes = append(nodes, node)
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", node.Url, nil)
		fmt.Print("Checking node ", node.Url, "...")
		if _, err := http.DefaultClient.Do(req); err == nil {
			nodes = append(nodes, node)
			fmt.Println(" ok")
		} else {
			fmt.Println(" not ok")
		}
		cancel()
	}
	return
}
