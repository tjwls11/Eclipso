from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from server.api import text_api, redaction_api, file_redact_api, ner_api
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules import common as common_module

app = FastAPI(title="Eclipso Redaction Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
app.include_router(text_api.router)
app.include_router(redaction_api.router)
app.include_router(file_redact_api.router)
app.include_router(ner_api.router)      

@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Eclipso Redaction Server is running", "docs": "/docs"}

@app.get("/health", include_in_schema=False)
async def health():
    # 캐시/재시작 확인용(클라이언트가 "새 코드가 올라갔는지" 확인할 때 사용)
    return {
        "ok": True,
        "rules": [p.get("name") for p in (PRESET_PATTERNS or []) if isinstance(p, dict)],
        "masking_support": {
            "xml_partial_masking": hasattr(common_module, "_mask_value_with_policy"),
            "modes": [
                "ps.keep_first_char",
                "ps.ps_twochar(mask_full)",
                "rrn.keep_birth6",
                "fgn.keep_birth6",
                "phone.keep_first_group",
                "card.keep_first4_last4",
                "account.keep_last4/keep_last3",
            ],
        },
    }