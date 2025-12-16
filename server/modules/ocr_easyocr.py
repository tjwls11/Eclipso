from __future__ import annotations

from typing import List, Dict, Any, Union
from pathlib import Path
from io import BytesIO

import numpy as np
from PIL import Image
import easyocr


ImageLike = Union[str, bytes, np.ndarray, Image.Image]

_reader: easyocr.Reader | None = None


def _get_reader(
    languages: list[str] | None = None,
    gpu: bool = False,
) -> easyocr.Reader:
    """
    EasyOCR Reader를 lazy-init 으로 하나만 유지.
    """
    global _reader

    if _reader is None:
        if languages is None:
            languages = ["ko", "en"]
        _reader = easyocr.Reader(languages, gpu=gpu)

    return _reader


def _image_to_ndarray(img: ImageLike) -> np.ndarray:
    """
    이미지 입력을 EasyOCR이 먹을 수 있는 numpy array로 변환.
    """
    if isinstance(img, np.ndarray):
        return img

    if isinstance(img, Image.Image):
        return np.array(img)

    if isinstance(img, bytes):
        return np.array(Image.open(BytesIO(img)))

    if isinstance(img, str):
        path = Path(img)
        with path.open("rb") as f:
            return np.array(Image.open(f))

    raise TypeError(f"Unsupported image type: {type(img)!r}")


def easyocr_blocks(
    img: ImageLike,
    min_conf: float = 0.3,
    gpu: bool = False,
) -> List[Dict[str, Any]]:
    """
    EasyOCR로 텍스트 + bbox + confidence 추출.

    반환 형식:
      [
        {
          "text": "9466-4480-0445-6876",
          "bbox": [x0, y0, x1, y1],    # 픽셀 좌표
          "conf": 0.92,
        },
        ...
      ]
    """
    reader = _get_reader(gpu=gpu)
    arr = _image_to_ndarray(img)

    results = reader.readtext(arr, detail=1)  # (box, text, conf)

    blocks: List[Dict[str, Any]] = []

    for box, text, conf in results:
        if conf < min_conf:
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
