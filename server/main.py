from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import text, redaction, redact_file

app = FastAPI()

# CORS 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 전역 헬스체크
@app.get("/health")
async def health():
    return {"ok": True}

# 라우터 등록
app.include_router(text.router)
app.include_router(redaction.router)
app.include_router(redact_file.router)  # ← /redact/file 404 방지
