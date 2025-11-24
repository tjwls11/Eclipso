from __future__ import annotations
from typing import List, Dict, Any
import re


# LC 상수들
_LC_INLINE_DELIMS = re.compile(r"^[\s·,/\-]+$") 
_LC_ROAD_SUFFIX = re.compile(r"(로|길)$")       

_LC_BUILDING_KEYWORDS = re.compile(
    r"(상가|아파트|빌딩|빌라|오피스텔|프라자|플라자|타워|센터|몰)"
)


def _fill_line_lc_spans(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lines = text.splitlines(keepends=False)
    offset = 0
    line_ranges: List[tuple[int, int]] = []

    for line in lines:
        raw = line
        stripped = raw.strip()
        if not stripped:
            offset += len(raw) + 1
            continue

        has_digit = bool(re.search(r"\d", stripped))
        has_addr_kw = bool(
            re.search(r"[가-힣]{1,5}(시|군|구|읍|면|동|리)\b", stripped)
            or re.search(r"[가-힣0-9·]+(로|길|대로|도로)\b", stripped)
        )

        if not (has_digit and has_addr_kw):
            offset += len(raw) + 1
            continue

        left = offset + raw.find(stripped)
        right = left + len(stripped)
        line_ranges.append((left, right))
        offset += len(raw) + 1

    if not line_ranges:
        return lc_spans

    new_lc: List[Dict[str, Any]] = []

    for span in lc_spans:
        s, e = span["start"], span["end"]
        if any(ls <= s and e <= le for (ls, le) in line_ranges):
            continue
        new_lc.append(span)

    for (ls, le) in line_ranges:
        if any(
            sp.get("label") == "LC" and sp["start"] == ls and sp["end"] == le
            for sp in new_lc
        ):
            continue
        new_lc.append(
            {
                "start": ls,
                "end": le,
                "label": "LC",
                "source": "rule",
                "score": None,
            }
        )

    new_lc.sort(key=lambda x: (x["start"], x["end"]))
    return new_lc


def _extend_lc_road_and_number(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    n = len(text)

    for span in lc_spans:
        s = span["start"]
        e = span["end"]
        if e <= s:
            continue

        sub = text[s:e]
        end = e


        line_break = text.find("\n", e)
        line_end = n if line_break == -1 else line_break


        if _LC_ROAD_SUFFIX.search(sub):
            m = re.match(r"\s*(\d{1,5}(?:-\d{1,5})?(?:\s*번지)?)", text[end:line_end])
            if m and m.group(1):
                end = min(line_end, end + m.end())

        pos = end
        while True:
            m2 = re.match(r"\s*(\d{1,5}\s*[동층호])", text[pos:line_end])
            if m2 and m2.group(1):
                pos += m2.end()
                end = min(line_end, pos)
                continue

            m3 = re.match(r"\s*\([^()\n]{1,40}\)", text[pos:line_end])
            if m3:
                pos += m3.end()
                end = min(line_end, pos)
                continue

            break

        if end != e:
            span = {**span, "end": end, "source": span.get("source") or "rule"}

        out.append(span)

    return out


def _looks_like_building_line(line: str) -> bool:

    stripped = line.strip()
    if not stripped:
        return False

    if not re.search(r"\d", stripped):
        return False

    if not _LC_BUILDING_KEYWORDS.search(stripped):
        return False

    return True


def _extend_lc_building_nextline(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    out: List[Dict[str, Any]] = []
    n = len(text)

    for span in lc_spans:
        s = span["start"]
        e = span["end"]

        line_break = text.find("\n", s)
        line_end = n if line_break == -1 else line_break

        if e < line_end:
            rest = text[e:line_end]
            if rest.strip():  
                out.append(span)
                continue
        if line_end >= n - 1:
            out.append(span)
            continue

        next_line_start = line_end + 1
        next_break = text.find("\n", next_line_start)
        next_line_end = n if next_break == -1 else next_break
        next_line = text[next_line_start:next_line_end]

        # 다음 줄이 "상가/아파트 + 호수" 같은 빌딩 라인이면 붙인다
        if _looks_like_building_line(next_line):
            span = {
                **span,
                "end": next_line_end,
                "source": span.get("source") or "rule",
            }

        out.append(span)

    return out


def _merge_inline_lc(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not lc_spans:
        return lc_spans

    lc_spans = sorted(lc_spans, key=lambda x: (x["start"], x["end"]))
    merged: List[Dict[str, Any]] = []

    cur = lc_spans[0]
    for nxt in lc_spans[1:]:
        cs, ce = cur["start"], cur["end"]
        ns, ne = nxt["start"], nxt["end"]

        if ns >= ce:
            gap = text[ce:ns]
            # 같은 줄이고, 허용 구분자만 있으면 병합
            if "\n" not in gap and _LC_INLINE_DELIMS.fullmatch(gap or " "):
                cur = {
                    **cur,
                    "end": ne,
                    "source": "rule",
                    "score": max(
                        cur.get("score") or 0.0,
                        nxt.get("score") or 0.0,
                    ),
                }
            else:
                merged.append(cur)
                cur = nxt
        else:
            # 이미 겹치는 경우는 나중 단계에서 정리
            merged.append(cur)
            cur = nxt

    merged.append(cur)
    return merged


def _filter_short_lc(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    n = len(text)

    for span in lc_spans:
        s = span["start"]
        e = span["end"]
        sub = text[s:e].strip()

        # 한글 글자수 계산
        hangul_chars = re.findall(r"[가-힣]", sub)
        hlen = len(hangul_chars)

        if hlen <= 2:
            # 스스로 로/길로 끝나면 유지
            if _LC_ROAD_SUFFIX.search(sub):
                out.append(span)
                continue

            # 바로 뒤에 건물번호가 붙어 있으면 유지
            look_ahead = text[e : min(n, e + 8)]
            if re.match(r"\s*\d", look_ahead):
                out.append(span)
                continue

            # 나머지는 제거
            continue

        out.append(span)

    return out


def _trim_lc_trailing_noise(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for span in lc_spans:
        s = span["start"]
        e = span["end"]
        sub = text[s:e]
        m = re.match(r"^(.*?)(\s+([^\s\d()\n]{1,2})\s*)$", sub)
        if not m:
            out.append(span)
            continue

        head = m.group(1)
        tail = m.group(3)  # 실제 꼬리 토막

        # tail 안의 한글 글자수
        hanguls = re.findall(r"[가-힣]", tail)

        # 한글 1글자 이하이고, 주소 키워드로 끝나지 않으면 잘라낸다
        if len(hanguls) <= 1 and not re.search(
            r"(시|군|구|읍|면|동|리|로|길|대로|도로|층|호|번지)$", tail
        ):
            trimmed_head = head.rstrip()
            new_end = s + len(trimmed_head)
            if new_end > s:
                out.append({**span, "end": new_end})
                continue

        # 그 외에는 그대로 유지
        out.append(span)

    return out


def _split_multi_city_lc(text: str, lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    city_pat = re.compile(r"[가-힣]{2,10}(시|군|구)")

    # 문서 전체에서 시/군/구 토큰 빈도 계산
    freq: Dict[str, int] = {}
    for span in lc_spans:
        sub = text[span["start"]:span["end"]]
        for m in city_pat.finditer(sub):
            city = m.group(0)
            freq[city] = freq.get(city, 0) + 1

    # 두 번 이상 반복되는 것만 주소 헤더로 본다
    dominant_cities = {c for (c, f) in freq.items() if f >= 2}
    if not dominant_cities:
        return lc_spans

    for span in lc_spans:
        s = span["start"]
        e = span["end"]
        sub = text[s:e]

        # 이 span 안에서 dominant city 만 사용
        matches = [m for m in city_pat.finditer(sub) if m.group(0) in dominant_cities]

        if not matches:
            out.append(span)
            continue

        # (1) 매치가 1개인 경우: 그 지점부터 LC 로 보고 앞부분(건물명)은 버린다.
        if len(matches) == 1:
            m = matches[0]
            seg_start = s + m.start()
            seg_end = e

            # 좌우 공백 정리
            while seg_start < seg_end and text[seg_start].isspace():
                seg_start += 1
            while seg_end > seg_start and text[seg_end - 1].isspace():
                seg_end -= 1

            if seg_end > seg_start:
                out.append(
                    {
                        **span,
                        "start": seg_start,
                        "end": seg_end,
                        "source": span.get("source") or "rule",
                    }
                )
            continue

        # (2) 매치가 2개 이상인 경우: 각 시/군/구별로 분리
        for i, m in enumerate(matches):
            seg_start = s + m.start()
            if i + 1 < len(matches):
                seg_end = s + matches[i + 1].start()
            else:
                seg_end = e

            # 좌우 공백 정리
            while seg_start < seg_end and text[seg_start].isspace():
                seg_start += 1
            while seg_end > seg_start and text[seg_end - 1].isspace():
                seg_end -= 1

            if seg_end <= seg_start:
                continue

            out.append(
                {
                    **span,
                    "start": seg_start,
                    "end": seg_end,
                    "source": span.get("source") or "rule",
                }
            )

    out.sort(key=lambda x: (x["start"], x["end"]))
    return out


def _resolve_lc_overlaps(lc_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def sort_key(sp: Dict[str, Any]):
        score = sp.get("score")
        score_val = float(score) if isinstance(score, (int, float)) else 0.0
        length = sp["end"] - sp["start"]
        src = (sp.get("source") or "").lower()
        is_rule = 1 if src == "rule" else 0
        return (-score_val, -length, is_rule, sp["start"], sp["end"])

    sorted_spans = sorted(lc_spans, key=sort_key)
    kept: List[Dict[str, Any]] = []

    def overlaps(a, b):
        return min(a["end"], b["end"]) > max(a["start"], b["start"])

    for sp in sorted_spans:
        if any(overlaps(sp, k) for k in kept):
            continue
        kept.append(sp)

    kept.sort(key=lambda x: (x["start"], x["end"]))
    return kept


def postprocess_lc_spans(text: str, spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lc = [s for s in spans if s.get("label") == "LC"]
    others = [s for s in spans if s.get("label") != "LC"]

    lc = _fill_line_lc_spans(text, lc)

    if lc:
        lc = _extend_lc_road_and_number(text, lc)
        lc = _extend_lc_building_nextline(text, lc)
        lc = _merge_inline_lc(text, lc)

        lc = _trim_lc_trailing_noise(text, lc)
        lc = _filter_short_lc(text, lc)
        lc = _split_multi_city_lc(text, lc)
        lc = _resolve_lc_overlaps(lc)

    return others + lc