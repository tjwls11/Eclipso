from fastapi import APIRouter, UploadFile, File, HTTPException, Response
from pathlib import Path
from .. import doc_redactor, hwp_redactor, ppt_redactor

router = APIRouter(tags=["redact"])

@router.post("/redact/file", response_class=Response)
async def redact_file(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()

    if ext == ".doc":
        out = doc_redactor.redact(file_bytes)
        return Response(content=out, media_type="application/msword")
    elif ext == ".hwp":
        out = hwp_redactor.redact(file_bytes)
        return Response(content=out, media_type="application/x-hwp")
    elif ext == ".ppt":
        out = ppt_redactor.redact(file_bytes)
        return Response(content=out, media_type="application/vnd.ms-powerpoint")
    else:
        raise HTTPException(400, f"지원하지 않는 포맷: {ext}")
