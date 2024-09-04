package config

type Node struct {
	Url    string
	PubKey string
}

var Nodes = []Node{
	{
		Url:    "http://localhost:8080",
		PubKey: "04f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f3a",
	},
	{
		Url:    "http://localhost:8081",
		PubKey: "59d9225473451efffe6b36dbcaefdbf7b1895de62084509a7f5b58bf01d06418",
	},
	{
		Url:    "http://localhost:8082",
		PubKey: "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14",
	},
}
