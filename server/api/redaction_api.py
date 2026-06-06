from __future__ import annotations

import json
import logging
import time
import re
import types
from typing import Dict, List, Optional, Literal, Tuple, Set, Any
from urllib.parse import quote

from fastapi import APIRouter, UploadFile, File, Form, Response, HTTPException
from server.core.schemas import DetectResponse, PatternItem, Box
from server.modules.pdf_module import detect_boxes_from_patterns, apply_redaction,extract_table_layout    
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.common import compile_rules

router = APIRouter(tags=["redaction"])
log = logging.getLogger("redaction.router")


def _run_validator(value: str, validator, rule_name: str = "") -> tuple[bool, str]:
    if not callable(validator):
        return True, ""
    
    try:
        try:
            result = bool(validator(value))
        except TypeError:
            # 일부 validator는 (value, opts) 형태를 사용하므로 두 번째 인자를 None으로 보냄
            result = bool(validator(value, None))
        
        if result:
            return True, ""
        
        # FAIL 원인 추론
        return False, _infer_fail_reason(value, rule_name)
    except Exception as e:
        return False, f"검증 예외: {str(e)[:50]}"


def _infer_fail_reason(value: str, rule_name: str) -> str:
    """규칙별로 FAIL 원인을 추론하여 반환"""
    import re
    from datetime import datetime
    
    def _digits(s: str) -> str:
        return re.sub(r"\D", "", s or "")
    
    d = _digits(value)
    r = rule_name.lower()
    
    # 주민등록번호
    if "rrn" in r:
        if len(d) != 13:
            return f"자릿수 오류 ({len(d)}자리, 13자리 필요)"
        # 날짜 검증
        try:
            dt = datetime.strptime(d[:6], "%y%m%d")
            if dt.date() > datetime.today().date():
                return "미래 날짜"
        except ValueError:
            return "유효하지 않은 날짜"
        # 체크섬
        weights = [2,3,4,5,6,7,8,9,2,3,4,5]
        total = sum(int(x) * w for x, w in zip(d[:-1], weights))
        chk = (11 - (total % 11)) % 10
        if chk != int(d[-1]):
            return "체크섬 불일치"
        return "검증 실패"
    
    # 외국인등록번호
    if "fgn" in r:
        if len(d) != 13:
            return f"자릿수 오류 ({len(d)}자리, 13자리 필요)"
        try:
            datetime.strptime(d[:6], "%y%m%d")
        except ValueError:
            return "유효하지 않은 날짜"
        if d[6] not in "5678":
            return f"성별코드 오류 ({d[6]}, 5-8 필요)"
        # 체크섬
        weights = [2,3,4,5,6,7,8,9,2,3,4,5]
        total = sum(int(x) * w for x, w in zip(d[:-1], weights))
        chk = (11 - (total % 11)) % 10
        chk = (chk + 2) % 10
        if chk != int(d[-1]):
            return "체크섬 불일치"
        return "검증 실패"
    
    # 전화번호
    if "phone" in r or "mobile" in r or "tel" in r:
        hyphen_cnt = value.count("-")
        if hyphen_cnt not in (0, 2):
            return f"하이픈 개수 오류 ({hyphen_cnt}개)"
        if "mobile" in r:
            if not d.startswith("010"):
                return "010으로 시작하지 않음"
            if len(d) != 11:
                return f"자릿수 오류 ({len(d)}자리, 11자리 필요)"
        else:  # city/landline
            if d.startswith("02"):
                if len(d) not in (9, 10):
                    return f"서울 번호 자릿수 오류 ({len(d)}자리)"
            elif len(d) not in (10, 11):
                return f"지역번호 자릿수 오류 ({len(d)}자리)"
        return "전화번호 형식 오류"
    
    # 카드번호
    if "card" in r:
        if len(d) not in (15, 16):
            return f"자릿수 오류 ({len(d)}자리, 15-16자리 필요)"
        # Luhn 알고리즘
        s = 0
        alt = False
        for ch in reversed(d):
            n = ord(ch) - 48
            if alt:
                n *= 2
                if n > 9:
                    n -= 9
            s += n
            alt = not alt
        if (s % 10) != 0:
            return "Luhn 체크섬 불일치"
        # IIN 검증
        if len(d) == 16:
            if d[0] not in "245689":
                return f"알 수 없는 카드사 (첫자리: {d[0]})"
        return "카드번호 형식 오류"
    
    # 운전면허
    if "driver" in r:
        if len(d) != 12:
            return f"자릿수 오류 ({len(d)}자리, 12자리 필요)"
        area = d[:2]
        valid_areas = {"11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26"}
        if area not in valid_areas:
            return f"지역코드 오류 ({area})"
        return "운전면허 형식 오류"
    
    # 이메일
    if "email" in r:
        if "@" not in value:
            return "@ 기호 없음"
        parts = value.split("@")
        if len(parts) != 2:
            return "@ 기호가 여러 개"
        if "." not in parts[1]:
            return "도메인에 . 없음"
        return "이메일 형식 오류"
    
    # 여권
    if "passport" in r:
        return "여권번호 형식 오류"
    
    return "검증 실패"


def _ensure_pdf(file: UploadFile) -> None:
    if file is None:
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")
    if file.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(status_code=400, detail="PDF 파일이 아닙니다.")


def _read_pdf(file: UploadFile) -> bytes:
    try:
        return file.file.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF 읽기 실패: {e}")


def _parse_patterns_json(patterns_json: Optional[str]) -> List[PatternItem]:
    if patterns_json is None:
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    s = str(patterns_json).strip()
    if not s or s.lower() in ("null", "none"):
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    try:
        obj = json.loads(patterns_json)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"patterns_json 파싱 실패: {e}")

    arr: List[Dict[str, Any]]
    if isinstance(obj, dict):
        if "patterns" in obj and isinstance(obj["patterns"], list):
            arr = obj["patterns"]
        else:
            raise HTTPException(
                status_code=400,
                detail="잘못된 patterns_json: 'patterns' 키에 리스트 필요",
            )
    elif isinstance(obj, list):
        arr = obj
    else:
        raise HTTPException(
            status_code=400,
            detail="잘못된 patterns_json: 리스트 또는 {'patterns': 리스트} 형태",
        )

    try:
        return [PatternItem(**p) for p in arr]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"잘못된 patterns 항목: {e}")


def _compile_patterns(items: List[PatternItem]) -> List[Any]:
    compiled: List[Any] = []
    for it in items:
        # PatternItem 속성 추출
        try:
            regex = getattr(it, "regex")
        except AttributeError:
            raise HTTPException(status_code=400, detail="PatternItem에 'regex' 누락")

        try:
            rp = re.compile(regex)
        except re.error as e:
            name_for_msg = getattr(it, "name", getattr(it, "label", "UNKNOWN"))
            raise HTTPException(
                status_code=400, detail=f"정규식 컴파일 실패({name_for_msg}): {e}"
            )

        # 네임스페이스로 래핑(+ compiled)
        ns = types.SimpleNamespace(**it.dict())
        setattr(ns, "compiled", rp)
        compiled.append(ns)
    return compiled


@router.post(
    "/redactions/detect",
    response_model=DetectResponse,
    summary="PDF 패턴 박스 탐지",
    description=(
        "PDF에서 정규식/패턴에 해당하는 텍스트 박스를 탐지하여"
        " 좌표(Box 리스트)로 반환한다."
    ),
)
async def detect(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(
        None,
        description="커스텀 패턴 정의(JSON 문자열, 생략 시 PRESET_PATTERNS 사용)",
    ),
):
    _ensure_pdf(file)
    pdf_bytes = _read_pdf(file)

    # 패턴 로드
    patterns = _load_patterns_json(patterns_json)   

    # 기본 구현은 PRESET_PATTERNS 그대로 사용
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)
    return DetectResponse(
        ok=True,
        patterns=patterns,
        boxes=boxes,
        preview_url=None,
    )


@router.post(
    "/redactions/apply",
    response_class=Response,
    summary="PDF 레닥션 적용",
    description="기본 정규식 패턴으로 레닥션 적용.",
)
async def apply(
    file: UploadFile = File(..., description="PDF 파일"),
):
    _ensure_pdf(file)
    pdf = _read_pdf(file)
    fill = "black"

    boxes = detect_boxes_from_patterns(
        pdf, [PatternItem(**p) for p in PRESET_PATTERNS]
    )
    out = apply_redaction(pdf, boxes, fill=fill)

    return Response(
        content=out,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="redacted.pdf"'},
    )


def _filter_overlapping_matches(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not matches:
        return matches
    
    # 우선순위가 높은 규칙 (이 규칙과 겹치는 다른 규칙의 FAIL은 제거)
    HIGH_PRIORITY_RULES = {"rrn", "fgn"}
    
    # 시작 위치로 정렬
    sorted_matches = sorted(matches, key=lambda x: (x.get("start", 0), -x.get("end", 0)))
    
    # 유효한 매칭의 범위 수집
    valid_ranges: List[Tuple[int, int]] = []
    for m in sorted_matches:
        if m.get("valid"):
            valid_ranges.append((m.get("start", 0), m.get("end", 0)))
    
    # 우선순위 높은 규칙의 범위 수집 (valid 여부 상관없이)
    high_priority_ranges: List[Tuple[int, int]] = []
    for m in sorted_matches:
        rule = str(m.get("rule", "")).lower()
        if rule in HIGH_PRIORITY_RULES:
            high_priority_ranges.append((m.get("start", 0), m.get("end", 0)))
    
    def overlaps_with_valid(start: int, end: int) -> bool:
        """주어진 범위가 유효한 매칭 범위와 겹치는지 확인"""
        for vs, ve in valid_ranges:
            if max(start, vs) < min(end, ve):
                return True
        return False
    
    def overlaps_with_high_priority(start: int, end: int) -> bool:
        """주어진 범위가 우선순위 높은 규칙과 겹치는지 확인"""
        for hs, he in high_priority_ranges:
            if max(start, hs) < min(end, he):
                return True
        return False
    
    # 필터링
    filtered: List[Dict[str, Any]] = []
    for m in sorted_matches:
        start = m.get("start", 0)
        end = m.get("end", 0)
        is_valid = m.get("valid", False)
        rule = str(m.get("rule", "")).lower()
        is_high_priority = rule in HIGH_PRIORITY_RULES
        
        if is_valid:
            # 유효한 매칭은 항상 유지
            filtered.append(m)
        elif is_high_priority:
            # 우선순위 높은 규칙의 무효 매칭도 유지
            if not overlaps_with_valid(start, end):
                filtered.append(m)
        else:
            # 낮은 우선순위 무효 매칭:
            # 1) 유효한 매칭과 겹치면 제거
            # 2) 우선순위 높은 규칙과 겹쳐도 제거
            if not overlaps_with_valid(start, end) and not overlaps_with_high_priority(start, end):
                filtered.append(m)
    
    return filtered


def match_text(text: str):
    try:
        if not isinstance(text, str):
            text = str(text)
        comp = compile_rules()

        matches: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}

        for rule_name, rx, need_valid, _prio, validator in comp:
            if rx is None:
                continue

            for m in rx.finditer(text):
                value = m.group(0)

                # --- validator로 OK / FAIL 판단 -------------------
                is_valid = True
                fail_reason = ""
                if need_valid:
                    is_valid, fail_reason = _run_validator(value, validator, rule_name)

                start = m.start()
                end = m.end()
                ctx_start = max(0, start - 20)
                ctx_end = min(len(text), end + 20)

                #유효/무효와 상관없이 "정규식에 한 번 걸렸으면" 전부 기록
                match_item: Dict[str, Any] = {
                    "rule": rule_name,
                    "value": value,
                    "start": start,
                    "end": end,
                    "context": text[ctx_start:ctx_end],
                    "valid": bool(is_valid),
                }
                # FAIL인 경우에만 원인 추가
                if not is_valid and fail_reason:
                    match_item["fail_reason"] = fail_reason
                
                matches.append(match_item)

                # counts에는 OK/FAIL 합계(= 정규식 매칭 총 개수)를 넣어준다.
                counts[rule_name] = counts.get(rule_name, 0) + 1

        # 겹치는 매칭 필터링: 유효한 매칭과 겹치는 무효 매칭 제거
        filtered_matches = _filter_overlapping_matches(matches)
        
        # counts 재계산 (필터링 후)
        filtered_counts: Dict[str, int] = {}
        for m in filtered_matches:
            rule = m.get("rule", "")
            filtered_counts[rule] = filtered_counts.get(rule, 0) + 1

        log.debug(
            "regex match count(total incl. invalid)=%d, after filter=%d, rules=%d",
            len(matches),
            len(filtered_matches),
            len(filtered_counts),
        )
        return {"items": filtered_matches, "counts": filtered_counts}

    except Exception as e:
        log.exception("match_text 내부 오류")
        raise HTTPException(status_code=500, detail=f"매칭 오류: {e}")

@router.post(
    "/redactions/tables",
    summary="PDF 표 레이아웃 탐지",
    description=(
        "pymupdf4llm으로 PDF 내 표 위치와 행/열 개수만 탐지\n"
        "- 입력: file(PDF)\n"
        "- 출력: { tables: [ { page, bbox, row_count, col_count }, ... ] }"
    ),
)
async def detect_tables(
    file: UploadFile = File(..., description="PDF 파일"),
):
    # 기존 유틸 재사용
    _ensure_pdf(file)
    pdf_bytes = _read_pdf(file)

    # pdf_module.extract_table_layout 호출
    try:
        data = extract_table_layout(pdf_bytes)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"표 레이아웃 추출 중 오류: {e}",
        )

    # 그대로 JSON 반환
    return data
