package config

import (
	"os"
	"strings"
	"testing"
)

const pk = "0b5c751e877223c66246f154198abcd9215f6fa3649fcfadeb9025bedd99e319"

func TestNodes(t *testing.T) {
	n := len(Nodes)
	for i := 0; i < 2; i++ {
		parseNodes(strings.NewReader("url1 " + pk + "\nurl2 pk"))
		if len(Nodes) != n+1 || Nodes[n] != (Node{"url1", pk}) {
			t.Fatal()
		}
	}
}

func TestSigs(t *testing.T) {
	f, _ := os.Open("sigs.tar")
	if checkSigCount([]byte("hello\n"), f) != 1 {
		t.Fatal()
	}
}
