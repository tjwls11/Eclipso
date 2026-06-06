from __future__ import annotations

import inspect
import json
import os
import re
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile
from server.api.redaction_api import match_text
from server.modules import doc_module, hwp_module, pdf_module, ppt_module, xls_module
from server.modules.ner_module import run_ner 
from server.modules.xml_redaction import xml_redact_to_file

router = APIRouter(prefix="/redact", tags=["redact"])

_HANGUL_RE = re.compile(r"^[\uAC00-\uD7A3]+$")
_MASK_DEBUG = os.getenv("ECLIPSO_MASK_DEBUG", "1") not in ("0", "false", "FALSE", "off", "OFF")


def _is_email_rule(rule_name: str) -> bool:
    return "email" in (rule_name or "").lower()

def _call_apply_text_redaction(pdf_bytes: bytes, spans: List[Dict[str, Any]]) -> bytes:
    fn = pdf_module.apply_text_redaction
    sig = inspect.signature(fn)

    if "patterns" in sig.parameters:
        if "extra_spans" in sig.parameters:
            return fn(pdf_bytes, extra_spans=spans, patterns=[])
        return fn(pdf_bytes, spans, [])

    old = getattr(pdf_module, "PRESET_PATTERNS", None)
    try:
        if old is not None:
            pdf_module.PRESET_PATTERNS = []
        if "extra_spans" in sig.parameters:
            return fn(pdf_bytes, extra_spans=spans)
        return fn(pdf_bytes, spans)
    finally:
        if old is not None:
            pdf_module.PRESET_PATTERNS = old


def _safe_load_json_list(s: Optional[str]) -> Optional[List[Any]]:
    if not s:
        return None
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, list) else None
    except Exception:
        return None


def _safe_load_json_dict(s: Optional[str]) -> Optional[Dict[str, Any]]:
    if not s:
        return None
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _subspan(base: Dict[str, Any], start: int, end: int) -> Dict[str, Any]:
    d = dict(base)
    d["start"] = int(start)
    d["end"] = int(end)
    if isinstance(base.get("text"), str):
        try:
            rel0 = int(start) - int(base.get("start", start))
            rel1 = int(end) - int(base.get("start", start))
            d["text"] = base["text"][max(0, rel0) : max(0, rel1)]
        except Exception:
            pass
    return d


def _apply_masking_policy_spans(
    spans: List[Dict[str, Any]],
    full_text: str,
    masking_policy: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not spans:
        return []
    pol = masking_policy or {}
    ps_mode = str(pol.get("ps") or "full")
    ps_twochar = str(pol.get("ps_twochar") or "default")
    rrn_mode = str(pol.get("rrn") or "full")
    fgn_mode = str(pol.get("fgn") or "full")
    phone_mode = str(pol.get("phone") or "full")
    card_mode = str(pol.get("card") or "full")

    out: List[Dict[str, Any]] = []
    
    def _subruns_from_indices(base_sp: Dict[str, Any], base_s: int, idxs: List[int]) -> List[Dict[str, Any]]:
        if not idxs:
            return []
        idxs2: List[int] = []
        for x in idxs:
            try:
                idxs2.append(int(x))
            except Exception:
                continue
        if not idxs2:
            return []
        idxs2 = sorted(set(i for i in idxs2 if i >= 0))

        runs: List[Tuple[int, int]] = []
        cur0: Optional[int] = None
        cur1: Optional[int] = None
        for i in idxs2:
            if cur0 is None:
                cur0, cur1 = i, i + 1
                continue
            if cur1 is not None and i == cur1:
                cur1 += 1
            else:
                if cur0 is not None and cur1 is not None and cur1 > cur0:
                    runs.append((cur0, cur1))
                cur0, cur1 = i, i + 1
        if cur0 is not None and cur1 is not None and cur1 > cur0:
            runs.append((cur0, cur1))

        return [_subspan(base_sp, base_s + a, base_s + b) for a, b in runs if b > a]

    def _digits_after_n(seg: str, keep_n: int) -> List[int]:
        idxs: List[int] = []
        dcnt = 0
        for i, ch in enumerate(seg or ""):
            if ch.isdigit():
                dcnt += 1
                if dcnt > keep_n:
                    idxs.append(i)
        return idxs

    def _digits_before_last_n(seg: str, keep_last_n: int) -> List[int]:
        digit_pos = [i for i, ch in enumerate(seg or "") if ch.isdigit()]
        if len(digit_pos) <= keep_last_n:
            return []
        return digit_pos[: max(0, len(digit_pos) - keep_last_n)]

    def _phone_mask_indices(seg: str) -> List[int]:
        # 첫 digit 그룹(지역번호/010 등)만 남기고 이후 digit만 마스킹
        m = re.search(r"\d+", seg or "")
        if not m:
            return []
        cut = m.end()
        # 하이픈/공백이 없는 번호(예: 01012345678, 021234567) 케이스
        if re.fullmatch(r"\d+", seg or ""):
            if (seg or "").startswith("02"):
                cut = 2
            elif (seg or "").startswith("0"):
                cut = 3
        idxs: List[int] = []
        for i, ch in enumerate(seg or ""):
            if i >= cut and ch.isdigit():
                idxs.append(i)
        return idxs

    def _card_mask_indices(seg: str) -> List[int]:
        # 앞 4/뒤 4 digit만 남기고 나머지 digit을 마스킹
        digit_pos = [i for i, ch in enumerate(seg or "") if ch.isdigit()]
        if len(digit_pos) <= 8:
            return []
        keep = set(digit_pos[:4] + digit_pos[-4:])
        return [i for i in digit_pos if i not in keep]
    for sp in spans:
        if not isinstance(sp, dict):
            continue
        try:
            s = int(sp.get("start"))
            e = int(sp.get("end"))
        except Exception:
            continue
        if e <= s:
            continue
        seg = str(sp.get("text") or full_text[s:e])

        lab = str(sp.get("label") or "").upper()
        rule = str(sp.get("rule") or sp.get("label") or "").lower()

        # --- PS: 성만 남기기 ---
        if lab == "PS" and ps_mode == "keep_first_char":
            hangul_idxs = [i for i, ch in enumerate(seg) if _HANGUL_RE.fullmatch(ch or "")]
            if len(hangul_idxs) <= 1:
                out.append(sp)
                continue
            out.extend(_subruns_from_indices(sp, s, hangul_idxs[1:]))
            continue

        # --- RRN/FGN: 생년월일(앞 6자리)만 남기기 ---
        if rrn_mode == "keep_birth6" and ("rrn" in rule or lab == "RRN"):
            idxs = _digits_after_n(seg, keep_n=6)
            if idxs:
                out.extend(_subruns_from_indices(sp, s, idxs))
            else:
                out.append(sp)
            continue

        if fgn_mode == "keep_birth6" and ("fgn" in rule or lab == "FGN"):
            idxs = _digits_after_n(seg, keep_n=6)
            if idxs:
                out.extend(_subruns_from_indices(sp, s, idxs))
            else:
                out.append(sp)
            continue

        # --- Phone: 지역번호/010만 남기기 ---
        if phone_mode == "keep_first_group" and ("phone" in rule or lab.startswith("PHONE")):
            idxs = _phone_mask_indices(seg)
            if idxs:
                out.extend(_subruns_from_indices(sp, s, idxs))
            else:
                out.append(sp)
            continue

        # --- Card: 앞4/뒤4만 남기기 ---
        if card_mode == "keep_first4_last4" and ("card" in rule or lab == "CARD"):
            idxs = _card_mask_indices(seg)
            if idxs:
                out.extend(_subruns_from_indices(sp, s, idxs))
            else:
                out.append(sp)
            continue

        out.append(sp)

    out.sort(key=lambda x: (int(x.get("start", 0)), int(x.get("end", 0))))
    return out


def _mask_text_for_hwp(rule_key: str, text: str, masking_policy: Optional[Dict[str, Any]]) -> Optional[str]:
    if text is None:
        return None
    s = str(text)
    pol = masking_policy or {}
    rk = str(rule_key or "").lower()

    # email은 전체 마스킹 유지(기존 로직과 동일하게 동작)
    if rk == "email":
        return None

    # 주민/외국인: 앞 6 digit만 유지
    if rk == "rrn" and str(pol.get("rrn") or "") == "keep_birth6":
        out = []
        dcnt = 0
        for ch in s:
            if ch.isdigit():
                dcnt += 1
                out.append(ch if dcnt <= 6 else "*")
            else:
                out.append(ch)
        return "".join(out)

    if rk == "fgn" and str(pol.get("fgn") or "") == "keep_birth6":
        out = []
        dcnt = 0
        for ch in s:
            if ch.isdigit():
                dcnt += 1
                out.append(ch if dcnt <= 6 else "*")
            else:
                out.append(ch)
        return "".join(out)

    # 전화: 첫 digit 그룹만 유지
    if rk in ("phone_mobile", "phone_city") and str(pol.get("phone") or "") == "keep_first_group":
        m = re.search(r"\d+", s)
        if not m:
            return None
        cut = m.end()
        if re.fullmatch(r"\d+", s):
            if s.startswith("02"):
                cut = 2
            elif s.startswith("0"):
                cut = 3
        out = []
        for i, ch in enumerate(s):
            if i >= cut and ch.isdigit():
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    # 카드: 앞4/뒤4 유지
    if rk == "card" and str(pol.get("card") or "") == "keep_first4_last4":
        digit_pos = [i for i, ch in enumerate(s) if ch.isdigit()]
        if len(digit_pos) <= 8:
            return None
        keep = set(digit_pos[:4] + digit_pos[-4:])
        out = []
        for i, ch in enumerate(s):
            if ch.isdigit() and i not in keep:
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    # 이름(PS): 첫 한글 글자만 유지
    if rk == "ps" and str(pol.get("ps") or "") == "keep_first_char":
        hangul_pos = [i for i, ch in enumerate(s) if _HANGUL_RE.fullmatch(ch or "")]
        if len(hangul_pos) <= 1:
            return None
        keep_i = hangul_pos[0]
        out = []
        for i, ch in enumerate(s):
            if _HANGUL_RE.fullmatch(ch or "") and i != keep_i:
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    return None


@router.post("/file", response_class=Response, summary="파일 레닥션")
async def redact_file(
    file: UploadFile = File(...),
    rules_json: Optional[str] = Form(None),
    ner_labels_json: Optional[str] = Form(None),
    ner_entities_json: Optional[str] = Form(None),
    masking_json: Optional[str] = Form(None),
):
    ext = Path(file.filename).suffix.lower()
    file_bytes = await file.read()
    src_name = file.filename or f"redacted{ext or ''}"
    stem = Path(src_name).stem or "redacted"
    out_name = f"{stem}_redacted{ext or ''}"
    from urllib.parse import quote as _url_quote
    encoded_fileName = _url_quote(out_name, safe="")

    rules: Optional[List[str]] = None
    ner_allowed: Optional[List[str]] = None

    if rules_json:
        try:
            obj = json.loads(rules_json)
            if isinstance(obj, list):
                rules = [str(x).strip() for x in obj]
        except Exception:
            rules = None

    if ner_labels_json:
        try:
            obj = json.loads(ner_labels_json)
            if isinstance(obj, list):
                ner_allowed = [str(x) for x in obj]
        except Exception:
            ner_allowed = None

    client_entities = _safe_load_json_list(ner_entities_json)
    masking_policy = _safe_load_json_dict(masking_json)
    if _MASK_DEBUG:
        try:
            print(f"[MASK][DEBUG] ext={ext} masking_policy={masking_policy}")
        except Exception:
            pass

    out: Optional[bytes] = None
    mime = "application/octet-stream"

    try:
        if ext == ".pdf":
            plain_result = pdf_module.extract_text_indexed(file_bytes) or {}
            plain_text = str(plain_result.get("full_text") or "")
            if not plain_text.strip():

                ocr_on = os.getenv("ECLIPSO_PDF_OCR_REDACT", "1") not in ("0", "false", "FALSE", "off", "OFF")
                if ocr_on:
                    try:
                        dpi = int(float(os.getenv("ECLIPSO_PDF_OCR_DPI", "220")))
                        min_conf = float(os.getenv("ECLIPSO_PDF_OCR_MINCONF", "0.25"))
                        embed_on = os.getenv("ECLIPSO_PDF_OCR_EMBED_IMAGES", "1") not in (
                            "0",
                            "false",
                            "FALSE",
                            "off",
                            "OFF",
                        )

                        allowed_lower: Optional[Set[str]] = None
                        if isinstance(rules, list) and rules:
                            allowed_lower = {str(x).strip().lower() for x in rules if str(x).strip()}

                        entity_texts: List[str] = []
                        try:
                            allowed_set: Optional[Set[str]] = None
                            if ner_allowed:
                                allowed_set = {str(x).upper() for x in ner_allowed}

                            for ent in (client_entities or []):
                                if not isinstance(ent, dict):
                                    continue
                                lab = str(ent.get("label") or "").upper()
                                if allowed_set is not None and lab and lab not in allowed_set:
                                    continue
                                t = str(ent.get("text") or "").strip()
                                if len(t) >= 2:
                                    entity_texts.append(t)
                        except Exception:
                            entity_texts = []

                        boxes: List[Any] = []
                        if embed_on:
                            try:
                                boxes.extend(
                                    pdf_module.detect_sensitive_boxes_from_embedded_images(
                                        file_bytes,
                                        min_conf=float(min_conf),
                                        allowed_rules=allowed_lower,
                                    )
                                )
                            except Exception as e:
                                if _MASK_DEBUG:
                                    print(f"[PDF][OCR][DEBUG] embedded_images OCR 실패 err={e}")

                        # NER 텍스트 기반 매칭(임베드 이미지 OCR)
                        if embed_on and entity_texts:
                            try:
                                boxes.extend(
                                    pdf_module.detect_boxes_from_embedded_image_targets(
                                        file_bytes,
                                        targets=entity_texts,
                                        min_conf=float(min_conf),
                                    )
                                )
                            except Exception as e:
                                if _MASK_DEBUG:
                                    print(f"[PDF][OCR][DEBUG] embedded_targets OCR 실패 err={e}")

                        try:
                            boxes.extend(
                                pdf_module.detect_sensitive_boxes_from_ocr(
                                    file_bytes,
                                    dpi=int(dpi),
                                    min_conf=float(min_conf),
                                    allowed_rules=allowed_lower,
                                )
                            )
                        except Exception as e:
                            if _MASK_DEBUG:
                                print(f"[PDF][OCR][DEBUG] page_render OCR 실패 err={e}")

                        # NER 텍스트 기반 매칭(페이지 렌더 OCR)
                        if entity_texts:
                            try:
                                boxes.extend(
                                    pdf_module.detect_boxes_from_ocr_targets(
                                        file_bytes,
                                        targets=entity_texts,
                                        dpi=int(dpi),
                                        min_conf=float(min_conf),
                                    )
                                )
                            except Exception as e:
                                if _MASK_DEBUG:
                                    print(f"[PDF][OCR][DEBUG] page_targets OCR 실패 err={e}")

                        if boxes:
                            if _MASK_DEBUG:
                                print(
                                    f"[PDF][OCR][DEBUG] boxes={len(boxes)} dpi={dpi} min_conf={min_conf} rules={len(allowed_lower or []) or 'ALL'} ner_texts={len(entity_texts)}"
                                )
                            out = pdf_module.apply_redaction(file_bytes, boxes, fill="black")
                            mime = "application/pdf"
                            return Response(
                                content=out,
                                media_type=mime,
                                headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_fileName}"},
                            )
                    except Exception as e:
                        if _MASK_DEBUG:
                            print(f"[PDF][OCR][DEBUG] OCR 레닥션 fallback 실패 err={e}")

                raise HTTPException(
                    400,
                    "PDF plain text가 비어 있습니다. (OCR 레닥션은 기본 ON이지만, 현재 설정으로 민감정보를 찾지 못했습니다. DPI/CONF를 조정해보세요)",
                )

            print(f"[PDF][DEBUG] plain_len={len(plain_text)} ner_allowed={ner_allowed}")

            # 1) 정규식 탐지 (plain text 기준)
            regex_result = match_text(plain_text)
            items = list(regex_result.get("items", []) or [])

            if isinstance(rules, list) and rules:
                allowed_lower: Set[str] = {str(x).strip().lower() for x in rules}
                items = [
                    it
                    for it in items
                    if str(it.get("rule") or it.get("name") or "").strip().lower() in allowed_lower
                ]

            regex_spans: List[Dict[str, Any]] = []
            for it in items:
                rule_name = str(it.get("rule") or it.get("name") or "")
                if it.get("valid") is False and not _is_email_rule(rule_name):
                    continue
                s, e = it.get("start"), it.get("end")
                if s is None or e is None:
                    continue
                s, e = int(s), int(e)
                if e > s:
                    regex_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": it.get("label") or rule_name or "REGEX",
                            "rule": rule_name,
                            "source": "regex",
                            "score": None,
                        }
                    )

            # 2) NER는 /ner/predict 기준으로만 생성
            ner_spans: List[Dict[str, Any]] = []
            allowed_set: Optional[Set[str]] = None
            if ner_allowed:
                allowed_set = {str(x).upper() for x in ner_allowed}

            if client_entities is not None:
                # UI가 /ner/predict entities를 보내면 그 결과를 그대로 사용
                for ent in client_entities:
                    if not isinstance(ent, dict):
                        continue
                    lab = str(ent.get("label") or "").upper()
                    s = ent.get("start")
                    e = ent.get("end")
                    if s is None or e is None:
                        continue
                    try:
                        s = int(s)
                        e = int(e)
                    except Exception:
                        continue
                    if e <= s:
                        continue
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue

                    ner_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": ent.get("score", None),
                        }
                    )

                print(f"[PDF][DEBUG] using client ner_entities={len(ner_spans)}")

            else:
                # UI가 entities를 안 보내도, 서버에서 /ner/predict와 동일하게 생성
                from server.api.ner_api import ner_predict_local, _auto_exclude_spans_by_regex

                exclude_spans = _auto_exclude_spans_by_regex(plain_text)
                labels = [str(x) for x in ner_allowed] if isinstance(ner_allowed, list) else None

                ents = ner_predict_local(
                    text=plain_text,
                    labels=labels,
                    exclude_spans=exclude_spans,
                )

                n = len(plain_text)
                for e in ents:
                    try:
                        s = max(0, min(n, int(e.get("start"))))
                        ed = max(0, min(n, int(e.get("end"))))
                    except Exception:
                        continue
                    if ed <= s:
                        continue

                    lab = str(e.get("label") or e.get("entity_group") or e.get("entity") or "").upper()
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue

                    ner_spans.append(
                        {
                            "start": s,
                            "end": ed,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": e.get("score", None),
                        }
                    )

                print(f"[PDF][DEBUG] server-side /ner/predict aligned ner_entities={len(ner_spans)}")

            # 3) regex 우선 병합 (겹치면 regex가 이김)
            used_ranges: List[Tuple[int, int]] = [(sp["start"], sp["end"]) for sp in regex_spans]

            ner_final: List[Dict[str, Any]] = []
            for sp in ner_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if s < 0 or e <= s:
                    continue
                if any(min(e, ue) > max(s, us) for us, ue in used_ranges):
                    continue
                ner_final.append(sp)
                used_ranges.append((s, e))

            final_spans = regex_spans + ner_final
            final_spans.sort(key=lambda x: (int(x["start"]), int(x["end"])))

            # 4) text 채우기
            enriched: List[Dict[str, Any]] = []
            for sp in final_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if e <= s or s >= len(plain_text):
                    continue
                s = max(0, s)
                e = min(len(plain_text), e)
                text = plain_text[s:e]
                if text.strip() == "":
                    continue
                enriched.append({**sp, "start": s, "end": e, "text": text})

            print(f"[PDF][DEBUG] enriched_spans={len(enriched)} sample={enriched[:3]}")

            # 5) 부분 마스킹 정책 적용(스팬을 쪼개서 부분만 레닥션)
            if masking_policy:
                if _MASK_DEBUG:
                    try:
                        print(f"[MASK][DEBUG] before_policy spans={len(enriched)} sample={enriched[:3]}")
                    except Exception:
                        pass
                enriched = _apply_masking_policy_spans(enriched, plain_text, masking_policy)
                if _MASK_DEBUG:
                    try:
                        print(f"[MASK][DEBUG] after_policy spans={len(enriched)} sample={enriched[:6]}")
                    except Exception:
                        pass

            # PDF는 partial masking이 있는 경우 "패턴 기반(전체)"와 섞이면 전체가 가려질 수 있어
            # 현재는 spans(start/end) -> boxes 변환 후 apply_redaction으로만 적용한다.
            boxes: List[Box] = []
            try:
                if isinstance(plain_result, dict) and plain_result.get("char_index"):
                    # pdf_module 내부 helper를 사용(동일 index 기반)
                    for sp in enriched:
                        try:
                            s_i = int(sp.get("start"))
                            e_i = int(sp.get("end"))
                        except Exception:
                            continue
                        if e_i <= s_i:
                            continue
                        boxes.extend(pdf_module._boxes_from_index_span(plain_result, s_i, e_i))  # type: ignore
            except Exception:
                boxes = []

            if boxes:
                out = pdf_module.apply_redaction(file_bytes, boxes, fill="black")
            else:
                # fallback
                out = _call_apply_text_redaction(file_bytes, enriched)
            mime = "application/pdf"

        elif ext == ".hwp":
            # NER spans (start-end)
            plain_text = hwp_module.extract_text(file_bytes).get("full_text") or ""
            if not plain_text.strip():
                raise HTTPException(400, "HWP plain text가 비어 있습니다.")

            print(f"[HWP][DEBUG] plain_len={len(plain_text)} ner_allowed={ner_allowed}")

            # 1) 정규식 탐지 (plain text 기준)
            regex_result = match_text(plain_text)
            items = list(regex_result.get("items", []) or [])

            if isinstance(rules, list) and rules:
                allowed_lower: Set[str] = {str(x).strip().lower() for x in rules}
                items = [
                    it
                    for it in items
                    if str(it.get("rule") or it.get("name") or "").strip().lower() in allowed_lower
                ]

            regex_spans: List[Dict[str, Any]] = []
            for it in items:
                rule_name = str(it.get("rule") or it.get("name") or "")
                if it.get("valid") is False and not _is_email_rule(rule_name):
                    continue
                s, e = it.get("start"), it.get("end")
                if s is None or e is None:
                    continue
                s, e = int(s), int(e)
                if e > s:
                    regex_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": it.get("label") or rule_name or "REGEX",
                            "source": "regex",
                            "score": None,
                        }
                    )

            # 2) NER는 /ner/predict 기준으로만 생성
            ner_spans: List[Dict[str, Any]] = []
            allowed_set: Optional[Set[str]] = None
            if ner_allowed:
                allowed_set = {str(x).upper() for x in ner_allowed}

            if client_entities is not None:
                # UI가 /ner/predict entities를 보내면 그 결과를 그대로 사용
                for ent in client_entities:
                    if not isinstance(ent, dict):
                        continue
                    lab = str(ent.get("label") or "").upper()
                    s = ent.get("start")
                    e = ent.get("end")
                    if s is None or e is None:
                        continue
                    try:
                        s = int(s)
                        e = int(e)
                    except Exception:
                        continue
                    if e <= s:
                        continue
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue

                    ner_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": ent.get("score", None),
                        }
                    )

                print(f"[HWP][DEBUG] using client ner_entities={len(ner_spans)}")

            else:
                from server.api.ner_api import ner_predict_local, _auto_exclude_spans_by_regex

                exclude_spans = _auto_exclude_spans_by_regex(plain_text)
                labels = [str(x) for x in ner_allowed] if isinstance(ner_allowed, list) else None

                ents = ner_predict_local(
                    text=plain_text,
                    labels=labels,
                    exclude_spans=exclude_spans,
                )

                n = len(plain_text)
                for e in ents:
                    try:
                        s = max(0, min(n, int(e.get("start"))))
                        ed = max(0, min(n, int(e.get("end"))))
                    except Exception:
                        continue
                    if ed <= s:
                        continue

                    lab = str(e.get("label") or e.get("entity_group") or e.get("entity") or "").upper()
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue

                    ner_spans.append(
                        {
                            "start": s,
                            "end": ed,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": e.get("score", None),
                        }
                    )

                print(f"[HWP][DEBUG] server-side /ner/predict aligned ner_entities={len(ner_spans)}")

            # 3) regex 우선 병합 (겹치면 regex가 이김)
            used_ranges: List[Tuple[int, int]] = [(sp["start"], sp["end"]) for sp in regex_spans]

            ner_final: List[Dict[str, Any]] = []
            for sp in ner_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if s < 0 or e <= s:
                    continue
                if any(min(e, ue) > max(s, us) for us, ue in used_ranges):
                    continue
                ner_final.append(sp)
                used_ranges.append((s, e))

            final_spans = regex_spans + ner_final
            final_spans.sort(key=lambda x: (int(x["start"]), int(x["end"])))

            # 4) text 채우기
            enriched: List[Dict[str, Any]] = []
            for sp in final_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if e <= s or s >= len(plain_text):
                    continue
                s = max(0, s)
                e = min(len(plain_text), e)
                text = plain_text[s:e]
                if text.strip() == "":
                    continue
                enriched.append({**sp, "start": s, "end": e, "text": text})

            print(f"[HWP][DEBUG] enriched_spans={len(enriched)} sample={enriched[:3]}")

            if masking_policy:
                if _MASK_DEBUG:
                    try:
                        print(f"[MASK][DEBUG] before_policy spans={len(enriched)} sample={enriched[:3]}")
                    except Exception:
                        pass
                for sp in enriched:
                    if not isinstance(sp, dict):
                        continue
                    lab = str(sp.get("label") or "").upper()
                    rk = str(sp.get("rule") or sp.get("label") or "").lower()
                    if lab == "PS":
                        rk = "ps"
                    repl = _mask_text_for_hwp(rk, sp.get("text"), masking_policy)
                    if isinstance(repl, str) and repl and isinstance(sp.get("text"), str):
                        if len(repl) == len(sp["text"]):
                            sp["replace_text"] = repl
                if _MASK_DEBUG:
                    try:
                        print(f"[MASK][DEBUG] after_policy spans={len(enriched)} sample={enriched[:6]}")
                    except Exception:
                        pass

            # hwp_module 구현 버전에 따라 masking_policy 인자를 받지 않을 수 있다.
            try:
                out = hwp_module.redact(file_bytes, spans=enriched, masking_policy=masking_policy)
            except TypeError:
                out = hwp_module.redact(file_bytes, spans=enriched)
            mime = "application/x-hwp"

        elif ext in (".doc", ".ppt", ".xls"):
            module_map = {
                ".doc": (doc_module, "application/msword"),
                ".ppt": (ppt_module, "application/vnd.ms-powerpoint"),
                ".xls": (xls_module, "application/vnd.ms-excel"),
            }
            mod, mime_guess = module_map[ext]

            plain_text = (mod.extract_text(file_bytes) or {}).get("full_text") or ""
            if not str(plain_text).strip():
                raise HTTPException(400, f"{ext} plain text가 비어 있습니다.")

            # 1) 정규식 탐지 (plain text 기준)
            regex_result = match_text(plain_text)
            items = list(regex_result.get("items", []) or [])

            if isinstance(rules, list) and rules:
                allowed_lower: Set[str] = {str(x).strip().lower() for x in rules}
                items = [
                    it
                    for it in items
                    if str(it.get("rule") or it.get("name") or "").strip().lower() in allowed_lower
                ]

            regex_spans: List[Dict[str, Any]] = []
            for it in items:
                rule_name = str(it.get("rule") or it.get("name") or "")
                if it.get("valid") is False and not _is_email_rule(rule_name):
                    continue
                s, e = it.get("start"), it.get("end")
                if s is None or e is None:
                    continue
                try:
                    s, e = int(s), int(e)
                except Exception:
                    continue
                if e > s:
                    regex_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": it.get("label") or rule_name or "REGEX",
                            "source": "regex",
                            "score": None,
                        }
                    )

            # 2) NER spans 생성(/ner/predict 기준)
            ner_spans: List[Dict[str, Any]] = []
            allowed_set: Optional[Set[str]] = None
            if ner_allowed:
                allowed_set = {str(x).upper() for x in ner_allowed}

            if client_entities is not None:
                for ent in client_entities:
                    if not isinstance(ent, dict):
                        continue
                    lab = str(ent.get("label") or "").upper()
                    s = ent.get("start")
                    e = ent.get("end")
                    if s is None or e is None:
                        continue
                    try:
                        s = int(s)
                        e = int(e)
                    except Exception:
                        continue
                    if e <= s:
                        continue
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue
                    ner_spans.append(
                        {
                            "start": s,
                            "end": e,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": ent.get("score", None),
                        }
                    )
            else:
                from server.api.ner_api import ner_predict_local, _auto_exclude_spans_by_regex

                exclude_spans = _auto_exclude_spans_by_regex(plain_text)
                labels = [str(x) for x in ner_allowed] if isinstance(ner_allowed, list) else None
                ents = ner_predict_local(text=plain_text, labels=labels, exclude_spans=exclude_spans)

                n = len(plain_text)
                for e in ents:
                    try:
                        s = max(0, min(n, int(e.get("start"))))
                        ed = max(0, min(n, int(e.get("end"))))
                    except Exception:
                        continue
                    if ed <= s:
                        continue
                    lab = str(e.get("label") or e.get("entity_group") or e.get("entity") or "").upper()
                    if allowed_set is not None and lab and lab not in allowed_set:
                        continue
                    ner_spans.append(
                        {
                            "start": s,
                            "end": ed,
                            "label": lab or "NER",
                            "source": "ner",
                            "score": e.get("score", None),
                        }
                    )

            # 3) regex 우선 병합 (겹치면 regex가 이김)
            used_ranges: List[Tuple[int, int]] = [(sp["start"], sp["end"]) for sp in regex_spans]
            ner_final: List[Dict[str, Any]] = []
            for sp in ner_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if s < 0 or e <= s:
                    continue
                if any(min(e, ue) > max(s, us) for us, ue in used_ranges):
                    continue
                ner_final.append(sp)
                used_ranges.append((s, e))

            final_spans = regex_spans + ner_final
            final_spans.sort(key=lambda x: (int(x["start"]), int(x["end"])))

            # 4) text 채우기
            enriched: List[Dict[str, Any]] = []
            for sp in final_spans:
                s, e = int(sp["start"]), int(sp["end"])
                if e <= s or s >= len(plain_text):
                    continue
                s = max(0, s)
                e = min(len(plain_text), e)
                text = plain_text[s:e]
                if text.strip() == "":
                    continue
                enriched.append({**sp, "start": s, "end": e, "text": text})

            if masking_policy:
                # OLE(.doc/.ppt/.xls)는 "문자열 치환" 기반 경로가 있어서 subspan(예: '1234')로 쪼개면 과마스킹 위험.
                # 따라서 전체 텍스트(old)를 유지하고, replace_text(동일 길이)만 붙여 모듈이 "old -> replace_text"로 교체하게 한다.
                for sp in enriched:
                    if not isinstance(sp, dict):
                        continue
                    lab = str(sp.get("label") or "").upper()
                    rk = str(sp.get("rule") or sp.get("label") or "").lower()
                    if lab == "PS":
                        rk = "ps"
                    repl = _mask_text_for_hwp(rk, sp.get("text"), masking_policy)
                    if isinstance(repl, str) and repl and isinstance(sp.get("text"), str):
                        if len(repl) == len(sp["text"]):
                            sp["replace_text"] = repl

            # 모듈이 spans를 받으면 전달 (doc/ppt/xls: NER 탐지 반영)
            try:
                out = mod.redact(file_bytes, spans=enriched)  # type: ignore[call-arg]
            except TypeError:
                out = mod.redact(file_bytes)

            mime = mime_guess

        elif ext in (".docx", ".pptx", ".xlsx", ".hwpx"):
            with tempfile.TemporaryDirectory() as tmpdir:
                src = os.path.join(tmpdir, f"src{ext}")
                dst = os.path.join(tmpdir, f"dst{ext}")
                with open(src, "wb") as f:
                    f.write(file_bytes)
                # ZIP-XML(docx/pptx/xlsx/hwpx)도 NER 결과를 반영해서 레닥션
                xml_redact_to_file(
                    src,
                    dst,
                    file.filename,
                    ner_entities=client_entities,
                    ner_allowed=ner_allowed,
                    masking_policy=masking_policy,
                )
                with open(dst, "rb") as f:
                    out = f.read()
            _xml_mime_map = {
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                ".hwpx": "application/hwp+zip",
            }
            mime = _xml_mime_map.get(ext, "application/octet-stream")

        else:
            raise HTTPException(400, f"지원하지 않는 포맷: {ext}")

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, f"{ext} 처리 중 오류: {e}")

    if not out:
        raise HTTPException(500, f"{ext} 레닥션 실패: 출력 없음")

    return Response(
        content=out,
        media_type=mime,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_fileName}"},
    )
