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
	{
		Url:    "https://liteworlds.quest/coinswap",
		pubKey: "a7eb3f598607a367f1e152f82f37ca7543a50b0e09d85bdae4d0476af8b2d32f",
	},
}
