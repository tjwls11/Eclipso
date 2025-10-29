# -*- coding: utf-8 -*-
from __future__ import annotations
import logging, traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from .routes.redaction import router as redaction_router

# ── 콘솔 로깅 포맷 고정 ───────────────────────────────────────────────────
root = logging.getLogger()
root.setLevel(logging.INFO)
fmt = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
    h = logging.StreamHandler()
    h.setFormatter(fmt)
    root.addHandler(h)

logging.getLogger("redaction.router").setLevel(logging.INFO)
logging.getLogger("xml_redaction").setLevel(logging.INFO)

# ── FastAPI ───────────────────────────────────────────────────────────────
app = FastAPI(title="Eclipso XML Demo")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 전역 예외 핸들러 ─────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def _unhandled_ex(request: Request, exc: Exception):
    logging.error("UNHANDLED %s %s", request.method, request.url.path)
    logging.error("TRACEBACK:\n%s", "".join(traceback.format_exc()))
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "path": request.url.path},
    )

@app.exception_handler(RequestValidationError)
async def _validation_ex(request: Request, exc: RequestValidationError):
    logging.error("VALIDATION ERROR %s %s -> %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

# 라우터
app.include_router(redaction_router)

@app.get("/healthz")
def healthz():
    return {"ok": True}
