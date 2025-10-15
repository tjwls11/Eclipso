from fastapi import UploadFile, HTTPException
from server.doc_redactor import extract_text as extract_doc_text
from server.ppt_redactor import extract_text as extract_ppt_text
from server.xls_extractor import extract_text_from_xls
from server.hwp_redactor import extract_text as extract_hwp_text
from server.pdf_redaction import extract_text as extract_pdf_text


async def extract_text_from_file(file: UploadFile):
    try:
        filename = (file.filename or "").lower()
        content_type = (file.content_type or "").lower()

        if not filename:
            raise HTTPException(status_code=415, detail="파일명이 비어 있습니다.")
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(status_code=415, detail="빈 파일입니다.")

        if filename.endswith(".doc") and not filename.endswith(".docx"):
            return extract_doc_text(file_bytes)

        elif filename.endswith(".ppt") and not filename.endswith(".pptx"):
            return extract_ppt_text(file_bytes)

        elif filename.endswith(".xls") and not filename.endswith(".xlsx"):
            return extract_text_from_xls(file_bytes)

        elif filename.endswith(".hwp"):
            return extract_hwp_text(file_bytes)

        elif filename.endswith(".pdf"):
            return extract_pdf_text(file_bytes)

        else:
            raise HTTPException(status_code=415, detail=f"지원하지 않는 파일 형식입니다: {filename}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"서버 내부 오류: {e}")
