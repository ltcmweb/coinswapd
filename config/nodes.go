package config

import (
	"bufio"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type Node struct {
	Url    string
	pubKey string
}

var Nodes = []Node{
	{
		Url:    "https://ltcmweb.xyz/coinswap",
		pubKey: "0b5c751e877223c66246f154198abcd9215f6fa3649fcfadeb9025bedd99e319",
	},
	{
		Url:    "https://liteworlds.quest/coinswap",
		pubKey: "a7eb3f598607a367f1e152f82f37ca7543a50b0e09d85bdae4d0476af8b2d32f",
	},
}

func fetchRemoteNodes() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(
		"https://raw.githubusercontent.com/ltcmweb/coinswapd/main/config/nodes.txt")
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()
	parseNodes(resp.Body)
}

func parseNodes(r io.Reader) {
	for s := bufio.NewScanner(r); s.Scan(); {
		ss := strings.Split(s.Text(), " ")
		if len(ss) < 2 {
			continue
		}
		node := Node{ss[0], ss[1]}
		if !slices.Contains(Nodes, node) && node.PubKey() != nil {
			Nodes = append(Nodes, node)
		}
	}
}
