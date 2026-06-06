from __future__ import annotations

import base64
import io
import os
from typing import Dict, List, Any, Optional

from PIL import Image


def bytes_to_data_uri(b: bytes, mime: str = "image/png") -> str:
    """바이트를 data URI로 변환"""
    return f"data:{mime};base64,{base64.b64encode(b).decode('ascii')}"


def downscale_for_display(img_bytes: bytes, mime: str = "image/png", max_dim: int = 1200) -> bytes:
    """표시용으로 이미지 다운스케일"""
    try:
        img = Image.open(io.BytesIO(img_bytes))
        w, h = img.size
        if w <= max_dim and h <= max_dim:
            return img_bytes
        
        ratio = min(max_dim / w, max_dim / h)
        new_w, new_h = int(w * ratio), int(h * ratio)
        img = img.resize((new_w, new_h), Image.LANCZOS)
        
        buf = io.BytesIO()
        fmt = "JPEG" if mime in ("image/jpeg", "image/jpg") else "PNG"
        img.save(buf, format=fmt, quality=85 if fmt == "JPEG" else None)
        return buf.getvalue()
    except Exception:
        return img_bytes


def render_pdf_pages(
    pdf_bytes: bytes,
    *,
    dpi: int = 120,
    max_pages: int = 10,
    max_dim: int = 1400,
) -> List[Dict[str, Any]]:
    """PDF 페이지를 이미지로 렌더링"""
    try:
        import fitz
    except ImportError:
        return []
    
    out: List[Dict[str, Any]] = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        limit = min(max_pages, len(doc))
        
        for i in range(limit):
            page = doc[i]
            mat = fitz.Matrix(dpi / 72, dpi / 72)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            png = pix.tobytes("png")
            
            # 다운스케일
            mime = "image/png"
            slim = downscale_for_display(png, mime, max_dim)
            
            out.append({
                "page": str(i + 1),
                "mime": mime,
                "data_uri": bytes_to_data_uri(slim, mime),
                "_bytes": png,  # OCR용 원본
            })
        
        doc.close()
    except Exception:
        pass
    
    return out


def extract_pdf_embedded_images(
    pdf_bytes: bytes,
    *,
    max_images_total: int = 25,
    max_images_per_page: int = 6,
    max_dim: int = 1200,
) -> List[Dict[str, Any]]:
    """PDF에서 임베디드 이미지 추출"""
    try:
        import fitz
    except ImportError:
        return []
    
    out: List[Dict[str, Any]] = []
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        
        for pno in range(len(doc)):
            if len(out) >= max_images_total:
                break
            
            page = doc[pno]
            imgs = page.get_images(full=True) or []
            page_count = 0
            
            for it in imgs:
                if len(out) >= max_images_total or page_count >= max_images_per_page:
                    break
                
                xref = int(it[0])
                try:
                    info = doc.extract_image(xref)
                    raw = info.get("image") or b""
                    if not raw:
                        continue
                    
                    ext = str(info.get("ext") or "png").lower()
                    mime_map = {"jpeg": "image/jpeg", "jpg": "image/jpeg", "png": "image/png", "gif": "image/gif"}
                    mime = mime_map.get(ext, "image/png")
                    
                    slim = downscale_for_display(raw, mime, max_dim)
                    name = f"page{pno+1}_xref{xref}.{ext}"
                    
                    out.append({
                        "page": pno + 1,
                        "name": name,
                        "mime": mime,
                        "data_uri": bytes_to_data_uri(slim, mime),
                        "_bytes": raw,  # OCR용 원본
                    })
                    page_count += 1
                except Exception:
                    continue
        
        doc.close()
    except Exception:
        pass
    
    return out


def extract_zip_images(file_bytes: bytes, *, max_images: int = 25) -> List[Dict[str, str]]:
    """ZIP 기반 문서(docx, pptx 등)에서 이미지 추출"""
    import zipfile
    
    out: List[Dict[str, str]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            for name in zf.namelist():
                if len(out) >= max_images:
                    break
                
                low = name.lower()
                if not any(low.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")):
                    continue
                
                try:
                    raw = zf.read(name)
                    if not raw:
                        continue
                    
                    ext = os.path.splitext(low)[-1]
                    mime_map = {".jpeg": "image/jpeg", ".jpg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp"}
                    mime = mime_map.get(ext, "image/png")
                    
                    slim = downscale_for_display(raw, mime)
                    
                    out.append({
                        "name": os.path.basename(name),
                        "mime": mime,
                        "data_uri": bytes_to_data_uri(slim, mime),
                        "_bytes": raw,
                    })
                except Exception:
                    continue
    except Exception:
        pass
    
    return out


def extract_ole_images(file_bytes: bytes, *, max_images: int = 25) -> List[Dict[str, str]]:
    """OLE 기반 문서(doc, ppt 등)에서 이미지 추출"""
    try:
        import olefile
    except ImportError:
        return []
    
    out: List[Dict[str, str]] = []
    try:
        ole = olefile.OleFileIO(io.BytesIO(file_bytes))
        
        for stream in ole.listdir():
            if len(out) >= max_images:
                break
            
            path = "/".join(stream)
            low = path.lower()
            
            # 이미지 스트림 찾기
            if not any(x in low for x in ["picture", "image", "pict", "data"]):
                continue
            
            try:
                raw = ole.openstream(stream).read()
                if len(raw) < 100:
                    continue
                
                # 이미지 헤더 확인
                if raw[:8] == b'\x89PNG\r\n\x1a\n':
                    mime = "image/png"
                elif raw[:2] == b'\xff\xd8':
                    mime = "image/jpeg"
                elif raw[:6] in (b'GIF87a', b'GIF89a'):
                    mime = "image/gif"
                else:
                    continue
                
                slim = downscale_for_display(raw, mime)
                name = stream[-1] if stream else "image"
                
                out.append({
                    "name": name,
                    "mime": mime,
                    "data_uri": bytes_to_data_uri(slim, mime),
                    "_bytes": raw,
                })
            except Exception:
                continue
        
        ole.close()
    except Exception:
        pass
    
    return out


def extract_images_any(file_bytes: bytes, filename: str, *, max_images: int = 25) -> List[Dict[str, str]]:
    """파일에서 이미지 추출 (ZIP/OLE 기반 문서)"""
    low = (filename or "").lower()
    ext = os.path.splitext(low)[-1]
    
    # 확장자 기반으로 ZIP/OLE 시도
    if ext in (".docx", ".pptx", ".xlsx", ".hwpx", ".zip"):
        imgs = extract_zip_images(file_bytes, max_images=max_images)
        if imgs:
            return imgs
    if ext in (".doc", ".ppt", ".xls", ".hwp"):
        imgs = extract_ole_images(file_bytes, max_images=max_images)
        if imgs:
            return imgs

    # fallback: zip 시도 → ole 시도
    imgs = extract_zip_images(file_bytes, max_images=max_images)
    if imgs:
        return imgs
    return extract_ole_images(file_bytes, max_images=max_images)
