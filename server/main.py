# server/main.py
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Redaction Demo API", version="2.0.0")

# CORS (필요 시 도메인 제한)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 정적 UI 서빙 (원하면 사용)
# app.mount("/ui", StaticFiles(directory="client", html=True), name="ui")

# 라우터 연결
# 프로젝트마다 파일명이 다를 수 있어 둘 다 시도
try:
    from .routes import redaction as redaction_routes
    app.include_router(redaction_routes.router)
except Exception:
    pass

try:
    # 네가 올린 파일명이 server/routes_redaction.py 라면 이쪽
    from . import routes_redaction as routes_redaction_module
    app.include_router(routes_redaction_module.router)
except Exception:
    pass

@app.get("/healthz")
def healthz():
    return {"ok": True}
