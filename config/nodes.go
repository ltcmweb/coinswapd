package config

type Node struct {
	Url    string
	pubKey string
}

var Nodes = []Node{
	{
		Url:    "http://localhost:8080",
		pubKey: "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13",
	},
	{
		Url:    "http://localhost:8081",
		pubKey: "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20",
	},
	{
		Url:    "http://localhost:8082",
		pubKey: "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14",
	},
}
