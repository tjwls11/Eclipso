from fastapi import APIRouter, UploadFile, File, Response, HTTPException
from pathlib import Path
from server.modules import doc_module, hwp_module, ppt_module, xls_module
from server.modules.pdf_module import redact

router = APIRouter(prefix="/redact", tags=["redact"])

@router.post("/file", response_class=Response)
async def redact_file(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()

    if ext == ".doc":
        out = doc_module.redact(file_bytes)
        mime = "application/msword"
        fname = "redacted.doc"
    elif ext == ".hwp":
        out = hwp_module.redact(file_bytes)
        mime = "application/x-hwp"
        fname = "redacted.hwp"
    elif ext == ".ppt":
        out = ppt_module.redact(file_bytes)
        mime = "application/vnd.ms-powerpoint"
        fname = "redacted.ppt"
    elif ext == ".xls":
        out = xls_module.redact(file_bytes)
        mime = "application/vnd.ms-excel"
        fname = "redacted.xls"
    elif ext == ".pdf":
        out = redact(file_bytes)
        mime = "application/pdf"
        fname = "redacted.pdf"
    else:
        raise HTTPException(400, f"지원하지 않는 포맷: {ext}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 추출된 내용 없음")

    return Response(
        content=out,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )
