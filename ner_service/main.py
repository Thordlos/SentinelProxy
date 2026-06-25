import os
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from cache import LRUCache
from ner_engine import NEREngine

app = FastAPI(title="SentinelProxy Local NER Service")

engine = NEREngine()
cache = LRUCache(
    maxsize=int(os.getenv("NER_CACHE_SIZE", "10000")),
    ttl=int(os.getenv("NER_CACHE_TTL", "300")),
)


class AnalyzeRequest(BaseModel):
    text: str
    entities: Optional[List[str]] = None


class Entity(BaseModel):
    type: str
    start: int
    end: int
    text: str
    score: float


class AnalyzeResponse(BaseModel):
    entities: List[Entity]


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    entity_types = req.entities or []
    cache_key = f"{hash(req.text)}:{','.join(sorted(entity_types))}"

    cached = cache.get(cache_key)
    if cached is not None:
        return AnalyzeResponse(entities=cached)

    raw_entities = engine.analyze(req.text, entity_types)
    entities = [Entity(**e) for e in raw_entities]
    cache.set(cache_key, entities)
    return AnalyzeResponse(entities=entities)


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": engine.is_loaded()}


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("NER_HOST", "0.0.0.0")
    port = int(os.getenv("NER_PORT", "8000"))
    workers = int(os.getenv("NER_WORKERS", "4"))
    uvicorn.run("main:app", host=host, port=port, workers=workers)
