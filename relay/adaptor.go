package relay

import (
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/aiproxy"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/ali"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/anthropic"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/aws"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/baidu"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/cloudflare"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/cohere"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/coze"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/deepl"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/gemini"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/ollama"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/openai"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/palm"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/proxy"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/replicate"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/tencent"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/vertexai"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/xunfei"
	"github.com/sentinelproxy/sentinelproxy/relay/adaptor/zhipu"
	"github.com/sentinelproxy/sentinelproxy/relay/apitype"
)

func GetAdaptor(apiType int) adaptor.Adaptor {
	switch apiType {
	case apitype.AIProxyLibrary:
		return &aiproxy.Adaptor{}
	case apitype.Ali:
		return &ali.Adaptor{}
	case apitype.Anthropic:
		return &anthropic.Adaptor{}
	case apitype.AwsClaude:
		return &aws.Adaptor{}
	case apitype.Baidu:
		return &baidu.Adaptor{}
	case apitype.Gemini:
		return &gemini.Adaptor{}
	case apitype.OpenAI:
		return &openai.Adaptor{}
	case apitype.PaLM:
		return &palm.Adaptor{}
	case apitype.Tencent:
		return &tencent.Adaptor{}
	case apitype.Xunfei:
		return &xunfei.Adaptor{}
	case apitype.Zhipu:
		return &zhipu.Adaptor{}
	case apitype.Ollama:
		return &ollama.Adaptor{}
	case apitype.Coze:
		return &coze.Adaptor{}
	case apitype.Cohere:
		return &cohere.Adaptor{}
	case apitype.Cloudflare:
		return &cloudflare.Adaptor{}
	case apitype.DeepL:
		return &deepl.Adaptor{}
	case apitype.VertexAI:
		return &vertexai.Adaptor{}
	case apitype.Proxy:
		return &proxy.Adaptor{}
	case apitype.Replicate:
		return &replicate.Adaptor{}
	}
	return nil
}
