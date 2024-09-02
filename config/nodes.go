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
}
