from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
from paddleocr import PaddleOCR


@dataclass
class OcrItem:
    bbox: Tuple[float, float, float, float]
    text: str
    score: float


_ocr = PaddleOCR(
    use_doc_orientation_classify=False,
    use_doc_unwarping=False,
    use_textline_orientation=False,
    lang="korean",
)


def run_paddle_ocr(image: np.ndarray, min_score: float = 0.5) -> List[OcrItem]:
    outputs = _ocr.predict(image)
    out: List[OcrItem] = []

    for res in outputs:
        data = getattr(res, "res", None)
        if data is None and isinstance(res, dict):
            data = res.get("res", res)
        if not isinstance(data, dict):
            continue

        rec_texts = data.get("rec_texts") or []
        rec_scores = data.get("rec_scores") or []

        boxes = data.get("rec_boxes", None)
        if boxes is None:
            boxes = data.get("dt_polys", None)
        if boxes is None:
            continue

        boxes_arr = np.asarray(boxes, dtype=float)

        if boxes_arr.ndim == 2 and boxes_arr.shape[1] == 8:
            boxes_arr = boxes_arr.reshape(-1, 4, 2)

        for txt, score, box in zip(rec_texts, rec_scores, boxes_arr):
            if not txt:
                continue
            s = float(score)
            if s < min_score:
                continue

            coords = np.asarray(box, dtype=float).reshape(-1, 2)
            xs = coords[:, 0]
            ys = coords[:, 1]
            x0, y0 = xs.min(), ys.min()
            x1, y1 = xs.max(), ys.max()

            out.append(
                OcrItem(
                    bbox=(float(x0), float(y0), float(x1), float(y1)),
                    text=str(txt).strip(),
                    score=s,
                )
            )

    return out
