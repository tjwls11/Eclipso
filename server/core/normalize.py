import re, unicodedata

_ZERO_WIDTH = re.compile(r"[\u200B\u200C\u200D\u2060\ufeff]")
_NBSP       = re.compile(r"[\u00A0\u2007\u202F]")
_DASHES     = re.compile(r"[\u2010\u2011\u2012\u2013\u2014\u2212\ufe63\u2043]")

def digits_only(s: str | None) -> str:
    return re.sub(r"\D+", "", s or "")

def strip_invisible(s: str) -> str:
    s = _ZERO_WIDTH.sub("", s)
    s = _NBSP.sub(" ", s)
    return s

#매핑 필요없는 곳에 사용하는 단순 정규화 방식
def normalization_text(s: str | None) -> str:
    if not s: return ""
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"\r\n?", "\n", s)
    s = strip_invisible(s)
    s = _DASHES.sub("-", s)
    s = s.replace("\t", " ")
    s = re.sub(r"[ \f\v]+", " ", s)
    s = "\n".join(re.sub(r"[ \t]+$", "", line) for line in s.split("\n"))
    return s

#정규화된 문자열과 원문 인덱스 매핑한 맵을 반환함.
# dict: {정규화된 인덱스: 원문 인덱스}
def normalization_index(s: str | None) -> tuple[str, dict[int, int]]:
    if not s:
        return "", {}

    # normalization_text()와 "동일한 결과 문자열"을 만들면서,
    # 정규화된 인덱스 -> 원문 인덱스를 매핑한다.
    out_chars: list[str] = []
    map_list: list[int] = []

    prev_space = False
    skip_next_lf = False  # \r\n? -> \n 정규화

    def _trim_line_trailing_spaces() -> None:
        # normalization_text: 각 라인 끝의 [ \t]+ 제거
        # (여기서는 탭이 이미 공백으로 변환되므로 공백만 제거)
        nonlocal prev_space
        while out_chars and out_chars[-1] == " ":
            out_chars.pop()
            map_list.pop()
        prev_space = False

    for i, ch in enumerate(s):
        if skip_next_lf and ch == "\n":
            skip_next_lf = False
            continue
        skip_next_lf = False

        # 0) \r\n? -> \n (normalization_text와 동일)
        if ch == "\r":
            _trim_line_trailing_spaces()
            out_chars.append("\n")
            map_list.append(i)
            skip_next_lf = True
            continue

        # 1) NFKC (문자 단위로 적용; 대부분 케이스에서 normalization_text와 동일)
        norm = unicodedata.normalize("NFKC", ch)

        for c in norm:
            # 2) strip_invisible: 제로폭 제거
            if _ZERO_WIDTH.match(c):
                continue

            # 3) NBSP류 → ' '
            c = _NBSP.sub(" ", c)

            # 4) 대시류 → '-'
            c = _DASHES.sub("-", c)

            # 5) 탭 → 공백
            if c == "\t":
                c = " "

            # 6) normalization_text의 [ \f\v]+ -> " " 를 반영
            if c == "\f" or c == "\v":
                c = " "

            # 7) 공백 압축(줄바꿈 제외)
            if c == "\n":
                _trim_line_trailing_spaces()
                out_chars.append("\n")
                map_list.append(i)
                prev_space = False
                continue

            if c == " ":
                if prev_space:
                    continue
                prev_space = True
            else:
                prev_space = False

            out_chars.append(c)
            map_list.append(i)

    # 마지막 라인 trailing space 제거
    _trim_line_trailing_spaces()

    text = "".join(out_chars)
    index_map = {j: raw_i for j, raw_i in enumerate(map_list)}
    return text, index_map

