from fastapi import APIRouter, UploadFile, HTTPException, Body
from server.extract_text import extract_text_from_file
from server.routes.redaction import match_text
from server.redac_rules import PRESET_PATTERNS


router = APIRouter()

@router.post("/text/extract")
async def extract_text(file: UploadFile):
    try:
        result = await extract_text_from_file(file)
        return result
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"서버 내부 오류: {e}")

@router.get("/text/rules")
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]

@router.post("/text/match")
async def match(req: dict = Body(...)):
    text = req.get("text", "")
    return match_text(text)