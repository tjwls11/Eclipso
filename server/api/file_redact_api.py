from fastapi import APIRouter, UploadFile, File, Response, HTTPException, Form
from pathlib import Path

from server.modules import doc_module, hwp_module, ppt_module, xls_module, pdf_module
from server.modules.xml_redaction import xml_redact_to_file

# 🔽 NER/정규식 병합을 위해 추가 (기존 main에는 없던 import)
from server.core.regex_utils import match_text
from server.modules.ner_module import run_ner
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY

import tempfile
import os
import traceback

router = APIRouter(prefix="/redact", tags=["redact"])

@router.post("/file", response_class=Response)
async def redact_file(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()

    out = None
    mime = "application/octet-stream"
    # ✅ main과 동일: 원본 파일명 유지(한글 인코딩 처리)
    encoded_fileName = file.filename.encode("utf-8", "ignore").decode("latin-1", "ignore")

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
            # ✅ main 유지 + NER/정규식 병합만 추가
            import fitz  # PyMuPDF

            try:
                doc = fitz.open(stream=file_bytes, filetype="pdf")
                text = "\n".join([p.get_text("text") or "" for p in doc])
                doc.close()
            except Exception:
                raise HTTPException(400, "PDF 텍스트 추출 실패")

            if not text.strip():
                raise HTTPException(400, "PDF 본문이 비어 있습니다.")

            # 정규식 결과 수집
            regex_res = match_text(text)
            regex_spans = []
            for it in (regex_res.get("items", []) or []):
                s, e = it.get("start"), it.get("end")
                # 0 인덱스도 허용하면서 유효 구간만
                if s is not None and e is not None and e > s:
                    regex_spans.append({
                        "start": int(s),
                        "end": int(e),
                        "label": it.get("rule"),
                        "source": "regex",
                    })

            # NER 실행 + 정책 병합
            policy = dict(DEFAULT_POLICY)
            ner_spans = run_ner(text=text, policy=policy)

            merger = MergePolicy(policy)
            final_spans, report = merger.merge(text, regex_spans, ner_spans)

            # 병합된 스팬으로 PDF 텍스트 레닥션
            out = pdf_module.apply_text_redaction(file_bytes, extra_spans=final_spans)
            mime = "application/pdf"

        elif ext in (".docx", ".pptx", ".xlsx", ".hwpx"):
            # ✅ main 그대로: XML 기반 레닥션 파이프
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
        print("🔥 [레닥션 오류 발생]")
        traceback.print_exc()
        raise HTTPException(500, f"{ext} 처리 중 오류: {e}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 출력 없음")

    # ✅ main 그대로: 원본 파일명 유지 + 인코딩 헤더
    return Response(
        content=out,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{encoded_fileName}"'}
    )
