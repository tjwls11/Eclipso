from __future__ import annotations

from typing import List, Dict, Any, Union
from pathlib import Path
from io import BytesIO

from PIL import Image

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore

try:
    import easyocr  # type: ignore
except Exception:  # pragma: no cover
    easyocr = None  # type: ignore

ImageLike = Union[str, bytes, "np.ndarray", Image.Image]

_reader = None


def _get_reader(
    languages: list[str] | None = None,
    gpu: bool = False,
) -> Any:
    # EasyOCR Reader lazy-init(1개 재사용)
    global _reader

    if easyocr is None:
        raise RuntimeError("easyocr is not installed")
    if np is None:
        raise RuntimeError("numpy is not installed")

    if _reader is None:
        if languages is None:
            languages = ["ko", "en"]
        _reader = easyocr.Reader(languages, gpu=gpu)

    return _reader


def _image_to_pil(img: ImageLike) -> Image.Image:
    if isinstance(img, Image.Image):
        return img

    if isinstance(img, bytes):
        return Image.open(BytesIO(img))

    if isinstance(img, str):
        path = Path(img)
        with path.open("rb") as f:
            return Image.open(f)

    if np is not None and isinstance(img, np.ndarray):  # type: ignore
        return Image.fromarray(img)  # type: ignore

    raise TypeError(f"Unsupported image type: {type(img)!r}")


def _image_to_ndarray(img: ImageLike):
    # 입력 이미지를 numpy array로 변환
    if np is None:
        raise RuntimeError("numpy is not installed")
    pil = _image_to_pil(img)
    return np.array(pil)  # type: ignore


def easyocr_blocks(
    img: ImageLike,
    min_conf: float = 0.3,
    gpu: bool = False,
) -> List[Dict[str, Any]]:
    # OCR 결과를 text/bbox/conf 블록 리스트로 표준화
    # 1) easyocr 사용 가능하면 easyocr로
    if easyocr is not None and np is not None:
        reader = _get_reader(gpu=gpu)
        arr = _image_to_ndarray(img)
        results = reader.readtext(arr, detail=1)

        blocks: List[Dict[str, Any]] = []
        for box, text, conf in results:
            try:
                conf = float(conf)
            except Exception:
                conf = 0.0
            if conf < float(min_conf):
                continue

            xs = [p[0] for p in box]
            ys = [p[1] for p in box]
            x0, y0 = float(min(xs)), float(min(ys))
            x1, y1 = float(max(xs)), float(max(ys))

            blocks.append(
                {
                    "text": str(text),
                    "bbox": [x0, y0, x1, y1],
                    "conf": float(conf),
                }
            )

        return blocks

    # 2) fallback: pytesseract (tesseract 설치 필요)
    try:
        import pytesseract  # type: ignore
        from pytesseract import Output  # type: ignore
    except Exception:
        return []

    try:
        pil = _image_to_pil(img)
        data = pytesseract.image_to_data(
            pil,
            lang="kor+eng",
            output_type=Output.DICT,
        )
    except Exception:
        return []

    blocks: List[Dict[str, Any]] = []
    try:
        n = len(data.get("text", []) or [])
    except Exception:
        n = 0

    conf_th = float(min_conf) * 100.0
    for i in range(n):
        try:
            txt = str((data.get("text") or [""])[i]).strip()
        except Exception:
            txt = ""
        if not txt:
            continue

        conf = (data.get("conf") or ["-1"])[i]
        try:
            conf = float(conf)
        except Exception:
            conf = -1.0
        if conf < conf_th:
            continue

        try:
            x = float((data.get("left") or [0])[i])
            y = float((data.get("top") or [0])[i])
            w = float((data.get("width") or [0])[i])
            h = float((data.get("height") or [0])[i])
        except Exception:
            continue

        blocks.append(
            {
                "text": txt,
                "bbox": [x, y, x + w, y + h],
                "conf": conf / 100.0,
            }
        )

    return blocks
