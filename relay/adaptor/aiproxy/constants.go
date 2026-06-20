package aiproxy

import "github.com/sentinelproxy/sentinelproxy/relay/adaptor/openai"

var ModelList = []string{""}

func init() {
	ModelList = openai.ModelList
}
