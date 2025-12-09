from fastapi import APIRouter, UploadFile, File, Response, HTTPException
from pathlib import Path
from typing import List, Dict, Any

from server.modules import doc_module, hwp_module, ppt_module, xls_module, pdf_module
from server.modules.xml_redaction import xml_redact_to_file

from server.api.redaction_api import match_text
from server.modules.ner_module import run_ner

import tempfile
import os
import traceback

router = APIRouter(prefix="/redact", tags=["redact"])


@router.post(
    "/file",
    response_class=Response,
    summary="파일 레닥션",
    description=(
        "지원 포맷: .doc, .hwp, .ppt, .xls, .pdf, .docx, .pptx, .xlsx, .hwpx\n"
    ),
)
async def redact_file(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()

    out: bytes | None = None
    mime = "application/octet-stream"
    encoded_fileName = file.filename.encode("utf-8", "ignore").decode(
        "latin-1", "ignore"
    )

    try:
        if ext == ".doc":
            out = doc_module.redact(file_bytes)
            mime = "application/msword"

        elif ext == ".hwp":
            out = hwp_module.redact(file_bytes)
            mime = "application/x-hwp"

        elif ext == ".ppt":
            out = ppt_module.redact(file_bytes)
            mime = "application/vnd.ms-powerpoint"

        elif ext == ".xls":
            out = xls_module.redact(file_bytes)
            mime = "application/vnd.ms-excel"

        elif ext == ".pdf":
            import fitz

            try:
                doc = fitz.open(stream=file_bytes, filetype="pdf")
                text = "\n".join([p.get_text("text") or "" for p in doc])
                doc.close()
            except Exception:
                raise HTTPException(400, "PDF 텍스트 추출 실패")

            if not text.strip():
                raise HTTPException(400, "PDF 본문이 비어 있습니다.")

            regex_result = match_text(text)
            regex_spans: List[Dict[str, Any]] = []
            for it in (regex_result.get("items", []) or []):
                s = it.get("start")
                e = it.get("end")
                if s is None or e is None or e <= s:
                    continue
                label = (
                    it.get("label")
                    or it.get("rule")
                    or it.get("name")
                    or "REGEX"
                )
                regex_spans.append(
                    {
                        "start": int(s),
                        "end": int(e),
                        "label": str(label),
                        "source": "regex",
                        "score": None,
                    }
                )

            masked_text = text
            if regex_spans:
                chars = list(text)
                for sp in regex_spans:
                    s = int(sp["start"])
                    e = int(sp["end"])
                    if s < 0:
                        s = 0
                    if e > len(chars):
                        e = len(chars)
                    for i in range(s, e):
                        if 0 <= i < len(chars) and chars[i] != "\n":
                            chars[i] = " "
                masked_text = "".join(chars)

            policy = {
                "chunk_size": 1500,
                "chunk_overlap": 50,
                "allowed_labels": None,
            }
            ner_spans: List[Dict[str, Any]] = run_ner(
                text=masked_text, policy=policy
            )

            all_spans = regex_spans + ner_spans
            all_spans.sort(
                key=lambda x: (x.get("start", 0), x.get("end", 0))
            )

            final_spans: List[Dict[str, Any]] = []
            used_ranges: List[tuple[int, int]] = []

            for span in all_spans:
                start = int(span.get("start", 0))
                end = int(span.get("end", 0))
                if end <= start:
                    continue
                overlaps = any(
                    min(end, used_end) > max(start, used_start)
                    for (used_start, used_end) in used_ranges
                )
                if overlaps:
                    continue
                final_spans.append(span)
                used_ranges.append((start, end))

            out = pdf_module.apply_text_redaction(
                file_bytes, extra_spans=final_spans
            )
            mime = "application/pdf"

        elif ext in (".docx", ".pptx", ".xlsx", ".hwpx"):
            with tempfile.TemporaryDirectory() as tmpdir:
                src_path = os.path.join(tmpdir, f"src{ext}")
                dst_path = os.path.join(tmpdir, f"dst{ext}")
                with open(src_path, "wb") as f:
                    f.write(file_bytes)
                xml_redact_to_file(src_path, dst_path, file.filename)
                with open(dst_path, "rb") as f:
                    out = f.read()
            mime = "application/zip"

        else:
            raise HTTPException(400, f"지원하지 않는 포맷: {ext}")

    except HTTPException:
        raise
    except Exception as e:
        print(" [레닥션 오류 발생]")
        traceback.print_exc()
        raise HTTPException(500, f"{ext} 처리 중 오류: {e}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 출력 없음")

    return Response(
        content=out,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{encoded_fileName}"'
        },
    )
