package config

type Node struct {
	Url    string
	pubKey string
}

var Nodes = []Node{
	{
		Url:    "https://ltcmweb.xyz/coinswap",
		pubKey: "0b5c751e877223c66246f154198abcd9215f6fa3649fcfadeb9025bedd99e319",
	},
}
