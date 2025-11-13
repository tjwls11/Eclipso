from fastapi import UploadFile, HTTPException
from server.modules import (
    doc_module, docx_module, ppt_module, pptx_module,
    xls_module, xlsx_module, hwp_module, hwpx_module, pdf_module
)

# 각 모듈은 반드시 extract_text(bytes) -> str 를 제공해야 함
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

async def extract_from_file(file: UploadFile) -> str:
    filename = (file.filename or "").lower()
    ext = "." + filename.split(".")[-1] if "." in filename else ""
    mod = MODULE_MAP.get(ext)
    if not mod:
        raise HTTPException(415, f"지원하지 않는 확장자: {ext}")
    file_bytes = await file.read()
    return mod.extract_text(file_bytes)
# :contentReference[oaicite:8]{index=8}
