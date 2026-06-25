import os
import re
from typing import List, Dict

import spacy

class NEREngine:
    """基于 spaCy 的本地 NER 引擎。"""

    def __init__(self):
        self.nlp = None
        model_name = os.getenv("SPACY_MODEL", "zh_core_web_sm")
        try:
            self.nlp = spacy.load(model_name)
        except OSError as e:
            # 启动后 /health 会暴露加载状态，避免直接崩溃。
            print(f"[NEREngine] failed to load spaCy model {model_name}: {e}")

    def is_loaded(self) -> bool:
        return self.nlp is not None

    def analyze(self, text: str, entity_filter: List[str] = None) -> List[Dict]:
        if not self.nlp or not text:
            return []

        if entity_filter is None:
            entity_filter = []

        results = []
        doc = self.nlp(text)

        # spaCy 标准 PERSON 实体
        for ent in doc.ents:
            mapped = self._map_type(ent.label_)
            if mapped is None:
                continue
            if entity_filter and mapped not in entity_filter:
                continue
            results.append({
                "type": mapped,
                "start": ent.start_char,
                "end": ent.end_char,
                "text": ent.text,
                "score": 0.85,
            })

        # 轻量启发式：@username
        if (not entity_filter) or "USER_NAME" in entity_filter:
            for m in re.finditer(r"@\w+", text):
                results.append({
                    "type": "USER_NAME",
                    "start": m.start(),
                    "end": m.end(),
                    "text": m.group(),
                    "score": 0.7,
                })

        return results

    @staticmethod
    def _map_type(spacy_label: str):
        mapping = {
            "PERSON": "PERSON_NAME",
            "PER": "PERSON_NAME",
        }
        return mapping.get(spacy_label)
