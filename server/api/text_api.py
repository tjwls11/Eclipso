from __future__ import annotations

from fastapi import APIRouter, UploadFile, HTTPException
from typing import Dict, Any, List
import logging

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text
from server.modules import pdf_module
from server.modules.pdf_module import extract_markdown as extract_pdf_markdown
from server.modules.ner_module import run_ner
from server.utils.media_extract import extract_images_any, render_pdf_pages, extract_pdf_embedded_images

router = APIRouter(prefix="/text", tags=["text"])
logger = logging.getLogger(__name__)

DEFAULT_POLICY: Dict[str, Any] = {
    "chunk_size": 1500,
    "chunk_overlap": 200,
    "allowed_labels": ["PS", "LC", "OG"],
}

def _effective_policy(user_policy: Any) -> Dict[str, Any]:
    p = dict(DEFAULT_POLICY)
    if isinstance(user_policy, dict):
        p.update(user_policy)
    if not isinstance(p.get("allowed_labels"), list) or not p.get("allowed_labels"):
        p["allowed_labels"] = list(DEFAULT_POLICY["allowed_labels"])
    try:
        p["chunk_overlap"] = int(p.get("chunk_overlap", DEFAULT_POLICY["chunk_overlap"]))
    except Exception:
        p["chunk_overlap"] = DEFAULT_POLICY["chunk_overlap"]
    try:
        p["chunk_size"] = int(p.get("chunk_size", DEFAULT_POLICY["chunk_size"]))
    except Exception:
        p["chunk_size"] = DEFAULT_POLICY["chunk_size"]
    return p

def _is_valid_span(span: Dict[str, Any]) -> bool:
    text = (span.get("text") or "").strip()
    label = (span.get("label") or "").upper()

    if not text:
        return False

    import re
    if re.fullmatch(r"[^\w\uAC00-\uD7A3]+", text):
        return False

    if label == "LC" and len(text) < 5:
        return False

    return True


@router.post("/extract")
async def extract_text(file: UploadFile):
    try:
        filename = (file.filename or "").lower()
        raw_bytes = await file.read()
        await file.seek(0)

        data = await extract_from_file(file)

        if filename.endswith(".pdf"):
            try:
                idx = pdf_module.extract_text_indexed(raw_bytes) or {}
                idx_text = idx.get("full_text")
                if isinstance(idx_text, str) and idx_text.strip():
                    data["full_text"] = idx_text
                    if isinstance(idx.get("pages"), list):
                        data["pages"] = idx["pages"]
            except Exception as e:
                logger.warning("PDF indexed text 생성 실패: %s", e)

            # 스캔본/이미지 PDF: 텍스트 레이어가 비면 OCR로 fallback
            try:
                import os

                ft0 = (data.get("full_text") if isinstance(data, dict) else "") or ""
                need_ocr = not (isinstance(ft0, str) and ft0.strip())
                ocr_on = os.getenv("ECLIPSO_PDF_OCR_EXTRACT", "1") not in ("0", "false", "FALSE", "off", "OFF")

                if need_ocr and ocr_on:
                    dpi = int(float(os.getenv("ECLIPSO_PDF_OCR_DPI", "220")))
                    min_conf = float(os.getenv("ECLIPSO_PDF_OCR_MINCONF", "0.25"))
                    max_pages = int(float(os.getenv("ECLIPSO_PDF_OCR_MAX_PAGES", "50")))
                    row_tol = float(os.getenv("ECLIPSO_PDF_OCR_ROW_TOL", "18.0"))
                    gpu = os.getenv("ECLIPSO_PDF_OCR_GPU", "0") in ("1", "true", "TRUE", "yes", "on", "ON")

                    ocr_res = pdf_module.extract_text_ocr(
                        raw_bytes,
                        dpi=dpi,
                        min_conf=min_conf,
                        max_pages=max_pages,
                        row_tol=row_tol,
                        gpu=gpu,
                    ) or {}
                    ocr_text = ocr_res.get("full_text")
                    if isinstance(ocr_text, str) and ocr_text.strip():
                        data["full_text"] = ocr_text
                        if isinstance(ocr_res.get("pages"), list):
                            data["pages"] = ocr_res["pages"]
                        data["ocr"] = True
            except Exception as e:
                logger.warning("PDF OCR fallback 실패: %s", e)

            try:
                md_info = extract_pdf_markdown(raw_bytes)
                if md_info.get("markdown"):
                    data["markdown"] = md_info["markdown"]
                    if "pages" in md_info:
                        data["pages_md"] = [
                            {"page": p.get("page"), "markdown": p.get("markdown", "")}
                            for p in (md_info.get("pages") or [])
                        ]
            except Exception as e:
                logger.warning("PDF markdown 생성 실패: %s", e)

        if isinstance(data, dict):
            md = data.get("markdown")
            if not isinstance(md, str) or not md.strip():
                ft = data.get("full_text")
                data["markdown"] = ft if isinstance(ft, str) else ""

        # 문서뷰어용 pages_view 생성
        # - base64 이미지가 split에 의해 잘리지 않도록 서버에서 "페이지 배열"로 내려준다.
        try:
            import os
            import io
            import json
            import base64
            from PIL import Image

            pages_view: List[str] = []
            max_images = int(float(os.getenv("ECLIPSO_VIEW_MAX_IMAGES", "25")))
            max_anns = int(float(os.getenv("ECLIPSO_VIEW_IMG_MAX_ANNS", "80")))
            max_anns_chars = int(float(os.getenv("ECLIPSO_VIEW_IMG_MAX_ANNS_CHARS", "24000")))
            view_minconf = str(os.getenv("ECLIPSO_VIEW_OCR_MINCONF", "0.15") or "0.15").strip()
            view_ocr_env = str(os.getenv("ECLIPSO_VIEW_OCR_ENV_PREFIX", "DOCX") or "DOCX").strip()
            if not view_ocr_env:
                view_ocr_env = "DOCX"

            # 이미지 OCR(정규식 룰 기반) 결과를 레이블로 변환(박스 라벨용)
            def _rule_to_label(rule: str) -> str:
                r = str(rule or "").lower()
                if "rrn" in r:
                    return "주민등록번호"
                if "fgn" in r:
                    return "외국인등록번호"
                if "card" in r:
                    return "카드번호"
                if "email" in r:
                    return "이메일"
                if "passport" in r:
                    return "여권번호"
                if "driver" in r:
                    return "운전면허번호"
                if "phone" in r or "tel" in r or "mobile" in r:
                    return "전화번호"
                return r or "UNKNOWN"

            def _b64_json(obj: object) -> str:
                try:
                    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    return base64.b64encode(raw).decode("ascii")
                except Exception:
                    return ""

            def _bytes_from_data_uri(uri: str) -> bytes:
                u = str(uri or "")
                if not u.startswith("data:") or "base64," not in u:
                    return b""
                try:
                    b64 = u.split("base64,", 1)[1]
                    return base64.b64decode(b64)
                except Exception:
                    return b""

            def _anns_for_image_bytes(img_bytes: bytes) -> tuple[str, str]:
                """Always returns (anns_b64, dbg_b64) where dbg_b64 is base64 encoded JSON."""
                def _dbg(info: Dict[str, Any]) -> str:
                    """Helper to always return base64 JSON for debug info."""
                    info.setdefault("env", view_ocr_env)
                    info.setdefault("minconf", view_minconf)
                    return _b64_json(info) or _b64_json({"error": "json-fail"})

                if not img_bytes:
                    return "", _dbg({"stage": "no-bytes", "bytes_len": 0})

                try:
                    from server.modules.ocr_image_redactor import detect_sensitive_ocr_blocks
                except Exception as e:
                    return "", _dbg({"stage": "import-fail", "error": repr(e)})

                envp = view_ocr_env
                old_llm = os.environ.get(f"{envp}_OCR_USE_LLM")
                old_conf = os.environ.get(f"{envp}_OCR_MINCONF")
                meta: Dict[str, Any] = {}
                matched: List[Any] = []
                w, h = 0, 0

                try:
                    os.environ[f"{envp}_OCR_USE_LLM"] = "0"
                    os.environ[f"{envp}_OCR_MINCONF"] = view_minconf

                    try:
                        img = Image.open(io.BytesIO(img_bytes))
                        img.load()
                    except Exception as e:
                        return "", _dbg({"stage": "image-open-fail", "error": repr(e), "bytes_len": len(img_bytes)})

                    w = int(getattr(img, "width", 0) or 0)
                    h = int(getattr(img, "height", 0) or 0)
                    if w <= 0 or h <= 0:
                        return "", _dbg({"stage": "bad-size", "w": w, "h": h})

                    try:
                        matched = (
                            detect_sensitive_ocr_blocks(
                                img,
                                env_prefix=envp,
                                filename="viewer",
                                comp=None,
                                meta=meta,
                            )
                            or []
                        )
                    except Exception as e:
                        meta["stage"] = "detect-fail"
                        meta["error"] = repr(e)
                        return "", _dbg(meta)

                finally:
                    if old_llm is None:
                        os.environ.pop(f"{envp}_OCR_USE_LLM", None)
                    else:
                        os.environ[f"{envp}_OCR_USE_LLM"] = old_llm

                    if old_conf is None:
                        os.environ.pop(f"{envp}_OCR_MINCONF", None)
                    else:
                        os.environ[f"{envp}_OCR_MINCONF"] = old_conf

                # Success path - build debug info
                meta["stage"] = "ok"
                meta["matched"] = len(matched)
                meta["w"] = w
                meta["h"] = h
                dbg_b64 = _dbg(meta)

                if not matched:
                    return "", dbg_b64

                out = []
                for m in matched:
                    if len(out) >= max_anns:
                        break
                    if not isinstance(m, dict):
                        continue
                    rule = str(m.get("rule") or "").lower().strip()
                    bbox = m.get("bbox")
                    if not rule or not bbox or not isinstance(bbox, (list, tuple)) or len(bbox) != 4:
                        continue
                    try:
                        x0, y0, x1, y1 = [float(v) for v in bbox]
                    except Exception:
                        continue
                    # clamp + normalize to 0..1
                    x0 = max(0.0, min(float(w), x0)) / float(w)
                    x1 = max(0.0, min(float(w), x1)) / float(w)
                    y0 = max(0.0, min(float(h), y0)) / float(h)
                    y1 = max(0.0, min(float(h), y1)) / float(h)
                    if x1 <= x0 or y1 <= y0:
                        continue

                    val = m.get("value")
                    txt = str(val) if isinstance(val, str) else ""
                    
                    # NER 매칭 vs REGEX 매칭 구분
                    if rule.startswith("ner_"):
                        label_part = rule[4:].upper() 
                        tag = f"NER·{label_part}"
                    else:
                        tag = f"REGEX·{_rule_to_label(rule)}"
                    
                    out.append(
                        {
                            "x0": round(x0, 4),
                            "y0": round(y0, 4),
                            "x1": round(x1, 4),
                            "y1": round(y1, 4),
                            "tag": tag,
                            "text": txt[:80],
                        }
                    )

                if not out:
                    return "", dbg_b64 or "out=0"

                # 1) full payload 시도
                b64 = _b64_json(out)
                if not b64:
                    return "", dbg_b64 or "b64-fail"
                if len(b64) <= max_anns_chars:
                    return b64, dbg_b64

                # 2) text 제거(크기 크게 줄어듦)
                slim = [{"x0": a["x0"], "y0": a["y0"], "x1": a["x1"], "y1": a["y1"], "tag": a["tag"]} for a in out]
                b64 = _b64_json(slim)
                if b64 and len(b64) <= max_anns_chars:
                    return b64, dbg_b64

                # 3) 개수 줄이기(그래도 너무 크면 일부만 내려준다)
                cur = slim
                while len(cur) > 5:
                    cur = cur[: max(5, int(len(cur) * 0.7))]
                    b64 = _b64_json(cur)
                    if b64 and len(b64) <= max_anns_chars:
                        return b64, dbg_b64

                return "", dbg_b64 or "too-big"

            if filename.endswith(".pdf"):
                mode = str(os.getenv("ECLIPSO_VIEW_PDF_RENDER_MODE", "auto") or "auto").strip().lower()

                dpi = int(float(os.getenv("ECLIPSO_VIEW_PDF_RENDER_DPI", "120")))
                max_pages = int(float(os.getenv("ECLIPSO_VIEW_PDF_RENDER_MAX_PAGES", "10")))
                max_images_per_page = int(float(os.getenv("ECLIPSO_VIEW_PDF_MAX_IMAGES_PER_PAGE", "6")))

                embedded = extract_pdf_embedded_images(
                    raw_bytes,
                    max_images_total=max_images,
                    max_images_per_page=max_images_per_page,
                )
                emb_by_page: Dict[int, List[Dict[str, str]]] = {}
                for it in embedded:
                    try:
                        pno = int(it.get("page") or 0)
                    except Exception:
                        pno = 0
                    if pno <= 0:
                        continue
                    emb_by_page.setdefault(pno, []).append(it)

                # page render는 필요할 때만 생성(auto/page)
                page_imgs = []
                by_page: Dict[int, str] = {}
                by_page_bytes: Dict[int, bytes] = {}
                if mode == "page" or mode == "auto":
                    page_imgs = render_pdf_pages(raw_bytes, dpi=dpi, max_pages=max_pages)
                    by_page = {int(p.get("page")): p.get("data_uri") for p in page_imgs if p.get("page")}
                    for p in page_imgs:
                        try:
                            pno = int(p.get("page") or 0)
                        except Exception:
                            pno = 0
                        if pno <= 0:
                            continue
                        b = p.get("_bytes")
                        if isinstance(b, (bytes, bytearray)):
                            by_page_bytes[pno] = bytes(b)

                if isinstance(data, dict) and isinstance(data.get("pages_md"), list) and data["pages_md"]:
                    for it in (data.get("pages_md") or []):
                        try:
                            pno = int(it.get("page") or 0)
                        except Exception:
                            pno = 0
                        md0 = str(it.get("markdown") or "")

                        # 1) embedded images 먼저(사진/차트 이미지)
                        if mode in ("auto", "embedded") and pno in emb_by_page and emb_by_page[pno]:
                            for j, img in enumerate(emb_by_page[pno], start=1):
                                uri = img.get("data_uri")
                                if not uri:
                                    continue
                                name = img.get("name") or f"page{pno}_img{j}"
                                anns = ""
                                dbg = ""
                                try:
                                    b = img.get("_bytes")
                                    if isinstance(b, (bytes, bytearray)):
                                        anns, dbg = _anns_for_image_bytes(bytes(b))
                                    else:
                                        raw = _bytes_from_data_uri(uri)
                                        if raw:
                                            anns, dbg = _anns_for_image_bytes(raw)
                                        else:
                                            dbg = "no-bytes"
                                except Exception as e:
                                    anns = ""
                                    dbg = f"exc:{repr(e)}"
                                md0 = (
                                    md0
                                    + "\n\n"
                                    + (
                                        f'<img src="{uri}" alt="{name}" loading="lazy" '
                                        f'data-eclipso="image" data-eclipso-name="{name}" data-eclipso-page="{pno}" '
                                        f'data-eclipso-anns="{anns}" data-eclipso-anns-debug="{dbg}" />'
                                    )
                                ).strip()

                        # 2) 스캔(텍스트 비어있는) 페이지는 전체 렌더가 필요(auto/page)
                        if mode == "page" or (mode == "auto" and not md0.strip()):
                            img_uri = by_page.get(pno)
                            if img_uri:
                                anns = ""
                                dbg = ""
                                try:
                                    b = by_page_bytes.get(pno)
                                    if isinstance(b, (bytes, bytearray)):
                                        anns, dbg = _anns_for_image_bytes(bytes(b))
                                    else:
                                        raw = _bytes_from_data_uri(img_uri)
                                        if raw:
                                            anns, dbg = _anns_for_image_bytes(raw)
                                        else:
                                            dbg = "no-bytes"
                                except Exception as e:
                                    anns = ""
                                    dbg = f"exc:{repr(e)}"
                                md0 = (
                                    md0
                                    + "\n\n---\n\n"
                                    + f'<img src="{img_uri}" alt="page {pno}" loading="lazy" data-eclipso="page" data-eclipso-page="{pno}" data-eclipso-anns="{anns}" data-eclipso-anns-debug="{dbg}" />'
                                ).strip()

                        pages_view.append(md0 if md0.strip() else "")
                else:
                    # markdown이 한 덩어리면 1페이지로 취급하고 렌더 이미지들을 뒤에 붙임
                    base_md = str((data or {}).get("markdown") or "")
                    if base_md.strip():
                        pages_view.append(base_md)

                    if mode in ("auto", "embedded") and embedded:
                        for k, img in enumerate(embedded, start=1):
                            uri = img.get("data_uri")
                            if not uri:
                                continue
                            nm = img.get("name") or f"image_{k}"
                            anns = ""
                            dbg = ""
                            try:
                                b = img.get("_bytes")
                                if isinstance(b, (bytes, bytearray)):
                                    anns, dbg = _anns_for_image_bytes(bytes(b))
                                else:
                                    raw = _bytes_from_data_uri(uri)
                                    if raw:
                                        anns, dbg = _anns_for_image_bytes(raw)
                                    else:
                                        dbg = "no-bytes"
                            except Exception as e:
                                anns = ""
                                dbg = f"exc:{repr(e)}"
                            pages_view.append(
                                (
                                    f'**Image {k} · {nm}**\n\n<img src="{uri}" alt="{nm}" loading="lazy" '
                                    f'data-eclipso="image" data-eclipso-name="{nm}" data-eclipso-anns="{anns}" data-eclipso-anns-debug="{dbg}" />'
                                )
                            )

                    if mode == "page" or (mode == "auto" and not base_md.strip()):
                        for i, p in enumerate(page_imgs, start=1):
                            uri = p.get("data_uri")
                            if not uri:
                                continue
                            anns = ""
                            dbg = ""
                            try:
                                b = p.get("_bytes")
                                if isinstance(b, (bytes, bytearray)):
                                    anns, dbg = _anns_for_image_bytes(bytes(b))
                                else:
                                    raw = _bytes_from_data_uri(uri)
                                    if raw:
                                        anns, dbg = _anns_for_image_bytes(raw)
                                    else:
                                        dbg = "no-bytes"
                            except Exception as e:
                                anns = ""
                                dbg = f"exc:{repr(e)}"
                            pages_view.append(
                                f'**Page {i}**\n\n<img src="{uri}" alt="page {i}" loading="lazy" data-eclipso="page" data-eclipso-page="{i}" data-eclipso-anns="{anns}" data-eclipso-anns-debug="{dbg}" />'
                            )

            else:
                # HWP/PPTX 파일은 이미지 추출/OCR 처리 생략 (텍스트만 표시)
                skip_image_exts = (".hwp", ".hwpx", ".pptx", ".ppt")
                skip_images = filename.endswith(skip_image_exts)
                
                base_md = str((data or {}).get("markdown") or "")
                if base_md.strip():
                    pages_view.append(base_md)
                
                # 이미지 추출 제외 대상이 아닌 경우에만 이미지 추출/표시
                if not skip_images:
                    imgs = extract_images_any(raw_bytes, filename, max_images=max_images)
                    for i, it in enumerate(imgs, start=1):
                        uri = it.get("data_uri")
                        if not uri:
                            continue
                        name = str(it.get("name") or f"image_{i}")
                        anns = ""
                        dbg = ""
                        try:
                            b = it.get("_bytes")
                            if isinstance(b, (bytes, bytearray)):
                                anns, dbg = _anns_for_image_bytes(bytes(b))
                            else:
                                raw = _bytes_from_data_uri(uri)
                                if raw:
                                    anns, dbg = _anns_for_image_bytes(raw)
                                else:
                                    dbg = "no-bytes"
                        except Exception as e:
                            anns = ""
                            dbg = f"exc:{repr(e)}"
                        pages_view.append(
                            (
                                f'**Image {i} · {name}**\n\n<img src="{uri}" alt="{name}" loading="lazy" '
                                f'data-eclipso="image" data-eclipso-name="{name}" data-eclipso-anns="{anns}" data-eclipso-anns-debug="{dbg}" />'
                            )
                        )

            if isinstance(data, dict) and pages_view:
                data["pages_view"] = pages_view
                # HWP/PPTX 파일은 이미지가 없으므로 has_images = False
                skip_image_exts_check = (".hwp", ".hwpx", ".pptx", ".ppt")
                data["has_images"] = not filename.endswith(skip_image_exts_check)
            elif isinstance(data, dict):
                data["pages_view"] = [str(data.get("markdown") or "")]
                data["has_images"] = False
        except Exception as e:
            logger.warning("pages_view 생성 실패: %s", e)

        return data

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("텍스트 추출 중 오류: filename=%s", getattr(file, "filename", None))
        raise HTTPException(500, detail=str(e))


@router.get("/policy")
async def get_policy():
    return DEFAULT_POLICY


@router.put("/policy")
async def set_policy(policy: dict):
    return {"ok": True, "policy": policy}


@router.get("/rules")
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]


@router.post("/match")
async def match(req: dict):
    text = (req or {}).get("text", "") or ""
    return match_text(text)


@router.post("/detect")
async def detect(req: dict):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = _effective_policy((req or {}).get("policy") or {})

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    regex_spans: List[Dict[str, Any]] = []
    if run_regex_opt:
        regex_result = match_text(text)
        for it in (regex_result.get("items", []) or []):
            if it.get("valid") is False:
                continue
            s, e = it.get("start"), it.get("end")
            if s is None or e is None:
                continue
            try:
                s_i = int(s)
                e_i = int(e)
            except Exception:
                continue
            if e_i <= s_i:
                continue

            regex_spans.append(
                {
                    "start": s_i,
                    "end": e_i,
                    "label": it.get("label") or it.get("rule"),
                    "text": text[s_i:e_i],
                    "source": "regex",
                    "score": None,
                }
            )

    ner_spans: List[Dict[str, Any]] = []
    if run_ner_opt:
        ner_spans = run_ner(text=text, policy=policy, exclude_spans=regex_spans)
        for sp in ner_spans:
            sp["source"] = "ner"

    final_spans: List[Dict[str, Any]] = []
    for sp in (regex_spans + ner_spans):
        if not _is_valid_span(sp):
            continue
        final_spans.append(sp)

    final_spans.sort(key=lambda x: (x["start"], x["end"]))

    return {
        "text": text,
        "final_spans": final_spans,
        "report": {
            "regex": len(regex_spans),
            "ner": len(ner_spans),
            "final": len(final_spans),
        },
    }


@router.post("/markdown")
async def extract_markdown_endpoint(file: UploadFile):
    filename = (file.filename or "").lower()
    raw_bytes = await file.read()

    # PDF는 pdf_module의 markdown을 사용
    if filename.endswith(".pdf"):
        return extract_pdf_markdown(raw_bytes)

    # 모듈이 markdown을 제공하면 우선 사용, 없으면 full_text를 markdown으로 반환
    await file.seek(0)
    data = await extract_from_file(file)
    if not isinstance(data, dict):
        raise HTTPException(500, "extract_from_file 결과 형식이 올바르지 않습니다.")
    md = data.get("markdown")
    if isinstance(md, str) and md.strip():
        return {"markdown": md}
    ft = data.get("full_text")
    return {"markdown": ft if isinstance(ft, str) else ""}
