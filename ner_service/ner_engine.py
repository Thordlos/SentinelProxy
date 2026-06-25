import os
import re
from typing import List, Dict

import spacy

class NEREngine:
    """本地 NER 引擎。

    优先使用 spaCy（默认 zh_core_web_sm）；如果模型未下载或加载失败，
    自动降级到 jieba 的词性标注（nr = 人名）作为 fallback。
    """

    def __init__(self):
        self.nlp = None
        self.jieba = None
        model_name = os.getenv("SPACY_MODEL", "zh_core_web_sm")
        try:
            self.nlp = spacy.load(model_name)
            print(f"[NEREngine] spaCy model loaded: {model_name}")
        except OSError as e:
            print(f"[NEREngine] spaCy model {model_name} not available: {e}")
            try:
                import jieba
                import jieba.posseg as pseg
                self.jieba = pseg
                print("[NEREngine] fallback to jieba POS tagging")
            except ImportError:
                print("[NEREngine] jieba not available, NER service will return empty results")

    def is_loaded(self) -> bool:
        return self.nlp is not None or self.jieba is not None

    def analyze(self, text: str, entity_filter: List[str] = None) -> List[Dict]:
        if not text:
            return []

        if entity_filter is None:
            entity_filter = []

        results = []

        if self.nlp is not None:
            results = self._analyze_spacy(text, entity_filter)
        elif self.jieba is not None:
            results = self._analyze_jieba(text, entity_filter)

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

        # Go 端按字节偏移处理，统一转成 UTF-8 字节偏移
        for r in results:
            r["start"], r["end"] = self._char_to_byte_offsets(text, r["start"], r["end"])

        return results

    @staticmethod
    def _char_to_byte_offsets(text: str, start: int, end: int):
        """将字符偏移量转换为 UTF-8 字节偏移量。"""
        prefix = text[:start]
        span = text[start:end]
        return len(prefix.encode("utf-8")), len(prefix.encode("utf-8")) + len(span.encode("utf-8"))

    def _analyze_spacy(self, text: str, entity_filter: List[str]) -> List[Dict]:
        results = []
        doc = self.nlp(text)
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
        return results

    def _analyze_jieba(self, text: str, entity_filter: List[str]) -> List[Dict]:
        results = []
        if entity_filter and "PERSON_NAME" not in entity_filter:
            return results
        last_idx = 0
        for word, flag in self.jieba.cut(text):
            if flag == "nr":
                start = text.find(word, last_idx)
                if start == -1:
                    continue
                results.append({
                    "type": "PERSON_NAME",
                    "start": start,
                    "end": start + len(word),
                    "text": word,
                    "score": 0.75,
                })
                last_idx = start + len(word)
            else:
                # 推进 last_idx 到当前词之后，避免跳过未匹配词导致后续重复词定位错误
                pos = text.find(word, last_idx)
                if pos != -1:
                    last_idx = pos + len(word)
        return results

    @staticmethod
    def _map_type(spacy_label: str):
        mapping = {
            "PERSON": "PERSON_NAME",
            "PER": "PERSON_NAME",
        }
        return mapping.get(spacy_label)
