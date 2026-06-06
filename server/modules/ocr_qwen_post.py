from __future__ import annotations

from typing import List, Dict, Any
import json
import logging

try:
    from ollama import Client  # type: ignore
    from ollama._types import ResponseError  # type: ignore
except Exception:  # pragma: no cover
    Client = None  # type: ignore
    ResponseError = Exception  # type: ignore


log = logging.getLogger(__name__)

QWEN_MODEL = "qwen2.5vl:3b"
OLLAMA_HOST = "http://localhost:11434"

_client: Client | None = None

def _get_client() -> Client:
    global _client
    if Client is None:
        raise RuntimeError("ollama is not installed")
    if _client is None:
        _client = Client(host=OLLAMA_HOST)
    return _client


def _select_candidates_for_llm(blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for idx, blk in enumerate(blocks):
        text = str(blk.get("text", "")).strip()
        if not text:
            continue

        if len(text) < 4 or len(text) > 40:
            continue

        digits = sum(ch.isdigit() for ch in text)
        if digits < 2 and "@" not in text and "-" not in text:
            continue

        item = dict(blk)
        item["_orig_index"] = idx
        item["_llm_text"] = text
        candidates.append(item)

    if len(candidates) > 40:

        def score(b: Dict[str, Any]) -> float:
            t = b["_llm_text"]
            digits = sum(ch.isdigit() for ch in t)
            return digits / max(len(t), 1)

        candidates.sort(key=score, reverse=True)
        candidates = candidates[:40]

    return candidates


def classify_blocks_with_qwen(
    blocks: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    import time
    from collections import Counter

    if not blocks:
        print("[OCR_QWEN] start blocks=0 -> return []", flush=True)
        return []

    if Client is None:
        # LLM 미설치 환경: 그대로 반환(서버 import 실패 방지)
        enriched: List[Dict[str, Any]] = []
        for blk in blocks:
            merged = dict(blk)
            merged.setdefault("kind", "none")
            merged.setdefault("normalized", merged.get("text", ""))
            enriched.append(merged)
        return enriched

    candidates = _select_candidates_for_llm(blocks)
    if not candidates:
        enriched: List[Dict[str, Any]] = []
        for blk in blocks:
            merged = dict(blk)
            merged.setdefault("kind", "none")
            merged.setdefault("normalized", merged.get("text", ""))
            enriched.append(merged)

        print(f"[OCR_QWEN] no candidates -> return enriched blocks={len(enriched)}", flush=True)
        return enriched

    prompt_lines = [
        "You are a privacy classification engine.",
        "For each text item, decide what kind of information it contains.",
        "",
        "For each item, choose kind from:",
        '- "card"   : credit/debit card-like number.',
        '- "phone"  : phone number (mobile or landline).',
        '- "email"  : email address or email-like string.',
        '- "id"     : government ID / passport / driver license / 주민등록번호 같은 것.',
        '- "none"   : not sensitive personal information.',
        "",
        "Return ONLY JSON with this schema:",
        "{",
        '  "items": [',
        "    {",
        '      "index": <int>,',
        '      "kind": "card" | "phone" | "email" | "id" | "none",',
        '      "normalized": "<string, normalized form of the text or same as input>"',
        "    },",
        "    ...",
        "  ]",
        "}",
        "",
        "Items to classify:",
    ]

    for tmp_idx, c in enumerate(candidates):
        prompt_lines.append(f"{tmp_idx}: {c['_llm_text']}")

    prompt = "\n".join(prompt_lines)

    t0 = time.perf_counter()
    print(
        f"[OCR_QWEN] start host={OLLAMA_HOST} model={QWEN_MODEL} "
        f"blocks={len(blocks)} candidates={len(candidates)}",
        flush=True,
    )

    client = _get_client()

    try:
        response = client.chat(
            model=QWEN_MODEL,
            messages=[{"role": "user", "content": prompt}],
            format="json",
        )
    except ResponseError as e:
        print(f"[OCR_QWEN] classify failed (ResponseError): {e}", flush=True)
        enriched: List[Dict[str, Any]] = []
        for blk in blocks:
            merged = dict(blk)
            merged.setdefault("kind", "none")
            merged.setdefault("normalized", merged.get("text", ""))
            enriched.append(merged)
        return enriched
    except Exception as e:
        print(f"[OCR_QWEN] classify failed (Exception): {e}", flush=True)
        enriched: List[Dict[str, Any]] = []
        for blk in blocks:
            merged = dict(blk)
            merged.setdefault("kind", "none")
            merged.setdefault("normalized", merged.get("text", ""))
            enriched.append(merged)
        return enriched

    content = response.get("message", {}).get("content")
    try:
        data = json.loads(content) if isinstance(content, str) else content
    except Exception as e:
        print(f"[OCR_QWEN] invalid json from model: {e}", flush=True)
        data = {"items": []}

    items = data.get("items", []) if isinstance(data, dict) else []
    tmp_map: Dict[int, Dict[str, Any]] = {}

    for it in items:
        try:
            idx = int(it.get("index", -1))
        except Exception:
            continue
        if idx < 0:
            continue
        tmp_map[idx] = it

    by_orig: Dict[int, Dict[str, Any]] = {}
    for tmp_idx, c in enumerate(candidates):
        orig_idx = int(c["_orig_index"])
        meta = tmp_map.get(tmp_idx)
        if meta:
            by_orig[orig_idx] = meta

    enriched: List[Dict[str, Any]] = []
    for idx, blk in enumerate(blocks):
        merged = dict(blk)
        meta = by_orig.get(idx)

        if meta:
            kind = meta.get("kind", "none")
            normalized = meta.get("normalized", merged.get("text", ""))
        else:
            kind = "none"
            normalized = merged.get("text", "")

        merged["kind"] = kind
        merged["normalized"] = normalized
        enriched.append(merged)

    dt_ms = int((time.perf_counter() - t0) * 1000)
    kinds = Counter((b.get("kind") or "none") for b in enriched)
    print(f"[OCR_QWEN] done ms={dt_ms} kind_counts={dict(kinds)}", flush=True)

    return enriched
