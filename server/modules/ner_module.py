from __future__ import annotations
from typing import List, Dict, Any, Tuple, Iterable
import re

# chunking
def _chunk_text(
    text: str,
    chunk_size: int = 1500,
    overlap: int = 50,
) -> List[Tuple[int, int, str]]:
    n = len(text)
    if n <= 0:
        return []

    chunks: List[Tuple[int, int, str]] = []
    i = 0
    while i < n:
        j = min(n, i + chunk_size)
        chunks.append((i, j, text[i:j]))
        if j == n:
            break
        i = max(0, j - overlap)
    return chunks


# label map
_LABEL_MAP = {
    "PS": "PS",
    "PERSON": "PS",
    "PER": "PS",
    "PEOPLE": "PS",
    "B-PER": "PS",
    "I-PER": "PS",

    "OG": "OG",
    "ORG": "OG",
    "ORGANIZATION": "OG",
    "INSTITUTION": "OG",
    "COMPANY": "OG",
    "B-ORG": "OG",
    "I-ORG": "OG",

    "LC": "LC",
    "LOCATION": "LC",
    "ADDRESS": "LC",
    "ADDR": "LC",
    "GPE": "LC",
    "PLACE": "LC",
    "FAC": "LC",
    "FACILITY": "LC",
    "B-LOC": "LC",
    "I-LOC": "LC",

    "DT": "DT",
    "DATE": "DT",
    "TIME": "DT",
    "DATETIME": "DT",

    "QT": "QT",
    "NUMBER": "QT",
    "QUANTITY": "QT",
    "CARDINAL": "QT",
    "NUM": "QT",
}


def _std_label(label: str) -> str:
    key = (label or "").strip().upper()
    return _LABEL_MAP.get(key, key)



# raw 응답에서 entity 리스트 추출
def _extract_entity_list(raw: Any) -> List[Any]:

    # dict 케이스
    if isinstance(raw, dict):
        for key in ("entities", "result", "preds", "prediction", "output"):
            val = raw.get(key)
            if isinstance(val, list):
                return val

        data = raw.get("data")
        if isinstance(data, list):
            while len(data) == 1 and isinstance(data[0], list):
                data = data[0]
            return data

    # 이미 리스트인 경우 그대로 사용
    if isinstance(raw, list):
        return raw

    return []


# normalize raw entities
def _normalize_raw_entities(
    raw: Any,
    chunk_start: int,
    chunk_text: str,
) -> List[Dict[str, Any]]:
    data = _extract_entity_list(raw)

    out: List[Dict[str, Any]] = []
    used: List[Tuple[int, int]] = []

    def _overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
        return min(a[1], b[1]) - max(a[0], b[0]) > 0

    if not isinstance(data, list):
        return out

    for e in data:
        if not isinstance(e, dict):
            continue

        # label 키 이름 다양성 대응
        std = _std_label(
            e.get("label")
            or e.get("entity")
            or e.get("entity_group")
            or ""
        )
        if not std:
            continue

        # 위치 정보 키 이름 다양성 대응
        start = (
            e.get("start")
            or e.get("begin")
            or e.get("start_idx")
            or e.get("offset_start")
        )
        end = (
            e.get("end")
            or e.get("finish")
            or e.get("end_idx")
            or e.get("offset_end")
        )

        txt = (e.get("text") or e.get("word") or "").strip()
        score = e.get("score")
        try:
            score = float(score) if score is not None else None
        except Exception:
            score = None

        # 위치 기반 매핑
        if start is not None and end is not None:
            try:
                s_local = int(start)
                t_local = int(end)
            except Exception:
                s_local = None
                t_local = None

            if s_local is not None and t_local is not None:
                # inclusive/exclusive 보정
                slice_now = chunk_text[s_local:t_local]
                if txt and slice_now != txt:
                    # 끝 인덱스 +1 보정
                    if (t_local + 1) <= len(chunk_text) and chunk_text[
                        s_local : t_local + 1
                    ] == txt:
                        t_local += 1
                    # 시작 인덱스 -1 보정
                    elif (
                        s_local > 0
                        and chunk_text[s_local - 1 : t_local] == txt
                    ):
                        s_local -= 1

                s = chunk_start + max(0, s_local)
                t = chunk_start + max(s_local, t_local)

                if t > s and not any(_overlap((s, t), r) for r in used):
                    out.append(
                        {
                            "start": s,
                            "end": t,
                            "label": std,
                            "source": "ner",
                            "score": score,
                        }
                    )
                    used.append((s, t))
                continue

        # fallback: 텍스트 기반 검색
        if txt:
            for m in re.finditer(re.escape(txt), chunk_text):
                s = chunk_start + m.start()
                t = chunk_start + m.end()
                if any(_overlap((s, t), r) for r in used):
                    continue
                out.append(
                    {
                        "start": s,
                        "end": t,
                        "label": std,
                        "source": "ner",
                        "score": score,
                    }
                )
                used.append((s, t))
                break

    return out


# entry
def run_ner(text: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    from server.api.ner_api import ner_predict_blocking

    chunk_size = int(policy.get("chunk_size", 1500))
    overlap = int(policy.get("chunk_overlap", 50))
    allowed = policy.get("allowed_labels", None)

    spans: List[Dict[str, Any]] = []

    for s, t, sub in _chunk_text(text, chunk_size=chunk_size, overlap=overlap):
        try:
            res = ner_predict_blocking(sub, labels=allowed)
            raw = res.get("raw", res)
            spans.extend(_normalize_raw_entities(raw, s, sub))
        except Exception:
            continue

    spans.sort(key=lambda x: (x["start"], x["end"]))
    return spans
