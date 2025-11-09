from fastapi import UploadFile, HTTPException
import zipfile

from server.modules import (
    doc_module,
    docx_module,
    ppt_module,
    pptx_module,
    xls_module,
    xlsx_module,
    hwp_module,
    hwpx_module,
    pdf_module,
)

MODULE_MAP = {
    ".doc": doc_module,
    ".docx": docx_module,
    ".ppt": ppt_module,
    ".pptx": pptx_module,
    ".xls": xls_module,
    ".xlsx": xlsx_module,
    ".hwp": hwp_module,
    ".hwpx": hwpx_module,
    ".pdf": pdf_module,
}

ZIP_BASED_EXTS = {".docx", ".pptx", ".xlsx", ".hwpx"}


async def extract_from_file(file: UploadFile):
    if file is None:
        raise HTTPException(400, "파일이 업로드되지 않았습니다.")

    filename = (file.filename or "").lower()
    ext = "." + filename.split(".")[-1] if "." in filename else ""
    mod = MODULE_MAP.get(ext)
    if not mod:
        raise HTTPException(415, f"지원하지 않는 확장자: {ext or '(확장자 없음)'}")

    try:
        await file.seek(0)
    except Exception:
        pass

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(400, "업로드된 파일이 비어 있습니다.")

    if ext in ZIP_BASED_EXTS and not file_bytes.startswith(b"PK"):
        raise HTTPException(400, "손상되었거나 잘못된 OOXML/HWPX 문서입니다.")

    try:
        return mod.extract_text(file_bytes)
    except zipfile.BadZipFile:
        raise HTTPException(400, "손상되었거나 잘못된 OOXML/HWPX 문서입니다.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"텍스트 추출 오류: {e}")
