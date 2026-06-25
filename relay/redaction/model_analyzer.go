package redaction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"

	"github.com/patrickmn/go-cache"
)

// modelAnalyzer 通过 HTTP 调用本地 NER 服务识别实体。
// 当 NER 服务不可用或超时时，会优雅回退（返回空实体），不影响主链路。
type modelAnalyzer struct {
	cfg      NERConfig
	opConfig *RedactionConfig
	client   *http.Client
	cache    *cache.Cache
}

// newModelAnalyzer 创建 NER 模型分析器。
func newModelAnalyzer(cfg NERConfig, opConfig *RedactionConfig) *modelAnalyzer {
	return &modelAnalyzer{
		cfg:      cfg,
		opConfig: opConfig,
		client:   &http.Client{Timeout: cfg.Timeout},
		cache:    cache.New(cfg.CacheTTL, cfg.CacheTTL*2),
	}
}

// nerRequest / nerResponse 定义与本地 NER 服务的通信协议。
type nerRequest struct {
	Text     string   `json:"text"`
	Entities []string `json:"entities,omitempty"`
}

type nerEntity struct {
	Type  string  `json:"type"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

type nerResponse struct {
	Entities []nerEntity `json:"entities"`
}

// Analyze 调用本地 NER 服务识别实体。任何失败都返回空结果，不抛错。
func (m *modelAnalyzer) Analyze(text string, entities []string) ([]Entity, error) {
	if m == nil || !m.cfg.Enabled || m.cfg.Endpoint == "" {
		return nil, nil
	}

	cacheKey := m.cacheKey(text, entities)
	if cached, found := m.cache.Get(cacheKey); found {
		return cached.([]Entity), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	reqBody, err := json.Marshal(nerRequest{Text: text, Entities: entities})
	if err != nil {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var result nerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil
	}

	var ents []Entity
	for _, e := range result.Entities {
		if e.Type == "" || e.Start < 0 || e.End > len(text) || e.End <= e.Start {
			continue
		}
		ents = append(ents, Entity{
			Type:     e.Type,
			Start:    e.Start,
			End:      e.End,
			Text:     e.Text,
			Score:    e.Score,
			RuleID:   "ner_model",
			Operator: m.opConfig.GetBuiltInEntityOperator(e.Type),
		})
	}

	m.cache.Set(cacheKey, ents, cache.DefaultExpiration)
	return ents, nil
}

func (m *modelAnalyzer) cacheKey(text string, entities []string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(text))
	key := fmt.Sprintf("%x", h.Sum64())
	if len(entities) > 0 {
		key += ":" + fmt.Sprintf("%x", fnvHashStrings(entities))
	}
	return key
}

func fnvHashStrings(ss []string) uint64 {
	h := fnv.New64a()
	for _, s := range ss {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}
