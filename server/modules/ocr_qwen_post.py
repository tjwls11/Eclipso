from __future__ import annotations

from typing import List, Dict, Any
import json
import logging

from ollama import Client
from ollama._types import ResponseError  # 예외 타입


log = logging.getLogger(__name__)

QWEN_MODEL = "qwen2.5vl:7b"  # 필요하면 "qwen2.5vl:3b" 처럼 더 작은 걸로 바꿔도 됨
OLLAMA_HOST = "http://localhost:11434"

# 한 번만 만들어서 재사용
_client: Client | None = None


def _get_client() -> Client:
    global _client
    if _client is None:
        _client = Client(host=OLLAMA_HOST)
    return _client


def _select_candidates_for_llm(blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    LLM에 보낼 가치가 있는 텍스트만 골라낸다.

    기준(적당히 타협):
      - 길이 4 ~ 40
      - 숫자가 2개 이상이거나, '@' 또는 '-' 포함
    """
    candidates: List[Dict[str, Any]] = []

    for idx, blk in enumerate(blocks):
        text = str(blk.get("text", "")).strip()
        if not text:
            continue

        if len(text) < 4 or len(text) > 40:
            continue

        digits = sum(ch.isdigit() for ch in text)
        if digits < 2 and "@" not in text and "-" not in text:
            # 거의 개인정보일 리 없는 텍스트는 스킵
            continue

        item = dict(blk)
        item["_orig_index"] = idx
        item["_llm_text"] = text
        candidates.append(item)

    # 너무 많으면 상위 40개만 (숫자 비율 높은 것 우선)
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
    """
    EasyOCR blocks를 받아서, Qwen으로 민감정보 종류를 분류하는 후처리.

    입력 blocks 예시:
      [
        {"text": "...", "bbox": [...], "conf": 0.93},
        ...
      ]

    반환 예시:
      [
        {
          "text": "...",
          "bbox": [...],
          "conf": 0.93,
          "kind": "card" | "phone" | "email" | "id" | "none",
          "normalized": "정제된 텍스트(옵션)",
        },
        ...
      ]
    """
    if not blocks:
        return []

    # LLM에 보낼 후보만 선정
    candidates = _select_candidates_for_llm(blocks)
    if not candidates:
        # 보낼 게 없으면 그냥 kind="none"만 붙여서 반환
        enriched: List[Dict[str, Any]] = []
        for blk in blocks:
            merged = dict(blk)
            merged.setdefault("kind", "none")
            merged.setdefault("normalized", merged.get("text", ""))
            enriched.append(merged)
        return enriched

    # Qwen에게 넘길 프롬프트 구성
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

    # 후보만 0..N-1 인덱스로 나열
    for tmp_idx, c in enumerate(candidates):
        t = c["_llm_text"]
        prompt_lines.append(f"{tmp_idx}: {t}")

    prompt = "\n".join(prompt_lines)

    client = _get_client()

    try:
        response = client.chat(
            model=QWEN_MODEL,
            messages=[{"role": "user", "content": prompt}],
            format="json",  # structured JSON output
        )
    except ResponseError as e:
        # LLM이 죽어도 서비스는 돌아가게: 그냥 kind="none"으로 처리
        log.error("Qwen classify failed: %s", e)
        print(f"[OCR_QWEN] classify failed: {e}")
        enriched: List[Dict[str, Any]] = []
        for blk in blocks:
            merged = dict(blk)
            merged.setdefault("kind", "none")
            merged.setdefault("normalized", merged.get("text", ""))
            enriched.append(merged)
        return enriched

    content = response["message"]["content"]

    if isinstance(content, str):
        data = json.loads(content)
    else:
        data = content

    items = data.get("items", []) or []

    # tmp index -> meta
    tmp_map: Dict[int, Dict[str, Any]] = {}
    for it in items:
        try:
            idx = int(it.get("index", -1))
        except Exception:
            continue
        if idx < 0:
            continue
        tmp_map[idx] = it

    # orig index -> meta 로 변환
    by_orig: Dict[int, Dict[str, Any]] = {}
    for tmp_idx, c in enumerate(candidates):
        orig_idx = int(c["_orig_index"])
        meta = tmp_map.get(tmp_idx)
        if not meta:
            continue
        by_orig[orig_idx] = meta

    # 최종 blocks에 kind/normalized 병합
    enriched: List[Dict[str, Any]] = []

    for idx, blk in enumerate(blocks):
        merged = dict(blk)
        meta = by_orig.get(idx)

        if meta:
            kind = meta.get("kind", "none")
            normalized = meta.get("normalized", merged.get("text", ""))
        else:
            # LLM에 안 보낸 애들
            kind = "none"
            normalized = merged.get("text", "")

        merged["kind"] = kind
        merged["normalized"] = normalized
        enriched.append(merged)

    return enriched
