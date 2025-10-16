import fitz  # PyMuPDF

def extract_pdf_text(data: bytes) -> dict:
    """PDF 바이트에서 페이지별 텍스트 추출"""
    pages = []
    full = []
    with fitz.open(stream=data, filetype="pdf") as doc:
        for i, page in enumerate(doc, start=1):
            txt = page.get_text("text") or ""
            pages.append({"page": i, "text": txt})
            full.append(f"===== [Page {i}] =====\n{txt}")
    return {"full_text": "\n".join(full), "pages": pages}


async def extract_text_from_file(file) -> dict:
    """
    UploadFile 받아서 PDF 또는 TXT 처리
    - PDF: PyMuPDF로 추출
    - TXT: 그대로 읽어서 반환
    """
    data = await file.read()
    name = (getattr(file, "filename", "") or "").lower()
    ctype = (getattr(file, "content_type", "") or "").lower()

    is_pdf = ctype == "application/pdf" or name.endswith(".pdf")
    is_txt = ctype.startswith("text/") or name.endswith(".txt")

    if is_pdf:
        return extract_pdf_text(data)

    if is_txt:
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("cp949", errors="ignore")
        return {"full_text": text, "pages": [{"page": 1, "text": text}]}

    raise ValueError("PDF 또는 TXT 파일만 지원합니다.")
