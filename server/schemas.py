# server/schemas.py
from __future__ import annotations

from typing import List, Optional, Literal
from pydantic import BaseModel

# =========================================================
# PDF 쪽 스키마 (원본 유지)
# =========================================================

class PatternItem(BaseModel):
    """
    PDF 감지에 사용하는 정규식 패턴 정의.
    - name: 패턴명
    - regex: 정규식
    - case_sensitive: 대소문자 구분 여부
    - whole_word: 단어 단위 매칭 여부
    - ensure_valid: validators 통과가 필요한지(원본 엔진에서 사용 가능)
    """
    name: str
    regex: str
    case_sensitive: bool = False
    whole_word: bool = False
    ensure_valid: bool = False


class Box(BaseModel):
    """
    PDF 상의 감지 결과 박스.
    라우터에서 pattern_name을 참조하므로 필수.
    """
    page: int
    x0: float
    y0: float
    x1: float
    y1: float

    # 감지된 텍스트 값(옵션)
    value: Optional[str] = None

    # 필터/통계를 위해 라우터가 사용하는 필드명
    pattern_name: Optional[str] = None

    # 선택: 유효성 여부 등 확장 필드(원본 사용 안 해도 무방)
    valid: Optional[bool] = None


class DetectResponse(BaseModel):
    """ /redactions/detect (PDF) 응답 """
    total_matches: int
    boxes: List[Box]


# (선택) 별칭 형태 – 기존 라우팅에선 DetectResponse 사용
class PdfScanResponse(BaseModel):
    total_matches: int
    boxes: List[Box]


# =========================================================
# XML(DOCX/XLSX/PPTX/HWPX) 스키마
# =========================================================

class XmlLocation(BaseModel):
    kind: Literal["docx", "xlsx", "pptx", "hwpx"]
    part: str  # ZIP 내부 경로 (예: word/document.xml, xl/sharedStrings.xml 등)
    para_idx: Optional[int] = None
    run_idx: Optional[int] = None
    cell_ref: Optional[str] = None
    start: Optional[int] = None   # 머지된 텍스트 기준 오프셋(간단화)
    end: Optional[int] = None


class XmlMatch(BaseModel):
    rule: str
    value: str
    valid: bool
    context: Optional[str] = None
    location: XmlLocation


class XmlScanResponse(BaseModel):
    file_type: Literal["docx", "xlsx", "pptx", "hwpx"]
    total_matches: int
    matches: List[XmlMatch]
    # ✅ 추가: PDF처럼 클라이언트 오른쪽 "추출 텍스트" 표시용
    extracted_text: Optional[str] = ""


# =========================================================
# 공용 다운로드 응답 (PDF/XML 공용)
# =========================================================

class RedactResult(BaseModel):
    file_name: str
    download_path: str  # 예: /redactions/download?path=/tmp/...
