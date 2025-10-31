from __future__ import annotations
import re
from typing import Any, Dict, List
from server.core.redaction_rules import PRESET_PATTERNS

def _compile(p): return p if isinstance(p, re.Pattern) else re.compile(p)
_RULES: Dict[str, re.Pattern] = {r["name"]: _compile(r["regex"]) for r in PRESET_PATTERNS}

def list_rule_names() -> List[str]:
    return list(_RULES.keys())

def match_text(text: str, rule_names: List[str] | None = None) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    names = rule_names or list(_RULES.keys())
    t = text or ""
    for name in names:
        pat = _RULES.get(name)
        if not pat: 
            continue
        for m in pat.finditer(t):
            s, e = m.start(), m.end()
            if e > s:
                items.append({"label": name, "start": s, "end": e, "text": t[s:e]})
    items.sort(key=lambda x: (x["start"], x["end"]))
    return {"items": items}
