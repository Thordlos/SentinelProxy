package redaction

import "sort"

// MergeEntities 合并来自多个 Analyzer 的实体，按位置去重。
// 排序规则：起始位置升序；相同起始位置，长度降序；长度相同，置信度降序。
// 重叠时保留最长匹配；长度相同时保留置信度更高的实体。
func MergeEntities(entities []Entity) []Entity {
	if len(entities) == 0 {
		return entities
	}

	sort.Slice(entities, func(i, j int) bool {
		if entities[i].Start != entities[j].Start {
			return entities[i].Start < entities[j].Start
		}
		lenI, lenJ := entities[i].End-entities[i].Start, entities[j].End-entities[j].Start
		if lenI != lenJ {
			return lenI > lenJ
		}
		return entities[i].Score > entities[j].Score
	})

	var merged []Entity
	current := entities[0]
	for i := 1; i < len(entities); i++ {
		next := entities[i]
		if next.Start < current.End {
			nextLen := next.End - next.Start
			currLen := current.End - current.Start
			if nextLen > currLen {
				current = next
			} else if nextLen == currLen && next.Score > current.Score {
				current = next
			}
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}
