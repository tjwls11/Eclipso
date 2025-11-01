// ===== helpers / config =====
const API_BASE = window.API_BASE || "";
const HWPX_VIEWER_URL = window.HWPX_VIEWER_URL || "";
const $ = (id) => document.getElementById(id);

const PREVIEW_ONLY_MATCHES = true;

function isPdfName(name) { return /\.pdf$/i.test(name || ""); }
function isXmlDoc(name) { return /\.(docx|xlsx|pptx|hwpx)$/i.test(name || ""); }
function extOf(name) { const m = (name || "").match(/\.([^.]+)$/); return (m ? m[1] : "").toLowerCase(); }
function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, m => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[m]));
}
function downloadBlob(blob, filenameFromHeader) {
  const a = document.createElement("a");
  const url = URL.createObjectURL(blob);
  a.href = url;
  if (filenameFromHeader) a.download = filenameFromHeader;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 800);
}
function setSaveVisible(show) {
  const b = $("btn-save-redacted"); if (!b) return;
  if (show) { b.classList.remove("hidden"); b.disabled = false; }
  else { b.classList.add("hidden"); b.disabled = true; }
}

// ===== tones (칩 색상) =====
const RULE_TONE = {
  rrn: "background:#ede9fe;color:#4c1d95;",
  fgn: "background:#ede9fe;color:#4c1d95;",
  email: "background:#e0f2fe;color:#075985;",
  phone_mobile: "background:#d1fae5;color:#065f46;",
  phone_city: "background:#d1fae5;color:#065f46;",
  card: "background:#ffedd5;color:#9a3412;",
  passport: "background:#e0e7ff;color:#3730a3;",
  driver_license: "background:#fce7f3;color:#9d174d;",
  default: "background:#f3f4f6;color:#374151;",
};
const toneStyle = (rule) => RULE_TONE[rule] || RULE_TONE.default;

// ===== masking (미리보기용) =====
const KEEP = new Set(["-", "_", " "]);
function maskPreview(val, rule) {
  if ((rule || "").toLowerCase() === "email") {
    let out = "";
    for (const ch of val || "") {
      if (ch === "@") out += "@";
      else if (/[A-Za-z0-9.]/.test(ch)) out += "*";
      else out += ch;
    }
    return out;
  }
  let out = "";
  for (const ch of val || "") {
    if (/[A-Za-z0-9]/.test(ch)) out += "*";
    else if (KEEP.has(ch)) out += ch;
    else out += ch;
  }
  return out;
}

// ===== normalize & filter =====
function normalizeMatchesText(fullText, matches) {
  return (matches || []).map(m => ({
    ...m,
    value:
      (m.value && String(m.value).trim()) ||
      (m.location && Number.isFinite(m.location.start) && Number.isFinite(m.location.end)
        ? fullText.slice(m.location.start, m.location.end).trim()
        : "")
  }));
}
function keepMeaningful(v) {
  if (!v) return false;
  return ((v.match(/[A-Za-z0-9]/g) || []).length >= 2);
}

// ===== group by rule =====
function groupByRule(fullText, matches, { fileType, valid /* 'ok'|'ng'|'all' */, masked }) {
  const groups = new Map();
  const seen = new Set();
  for (const m of matches) {
    if (fileType === "pdf" && !Number.isFinite(m.page)) continue;
    if (valid === "ok" && m.valid !== true) continue;
    if (valid === "ng" && m.valid !== false) continue;

    const rule = (m.rule || "unknown");
    let v = (m.value || "").trim();
    if (!v && m.location && Number.isFinite(m.location.start) && Number.isFinite(m.location.end)) {
      v = fullText.slice(m.location.start, m.location.end).trim();
    }
    if (!keepMeaningful(v)) continue;

    const show = masked ? maskPreview(v, rule) : v;
    const key = `${rule}:${show}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const arr = groups.get(rule) || [];
    arr.push(show);
    groups.set(rule, arr);
  }
  return new Map([...groups.entries()].sort((a, b) => a[0].localeCompare(b[0])));
}

// ===== tight preview (한 줄 = 한 카테고리) =====
function buildPreviewHtml_Grouped(fullText, matches, fileType) {
  const grouped = groupByRule(fullText, matches, { fileType, valid: "ok", masked: true });
  if (!grouped.size) return `<div style="font-size:12px;color:#9ca3af">감지된 항목 없음</div>`;

  let html = '<div style="font-size:13px;line-height:1.15;margin:0;padding:0">';
  grouped.forEach((vals, rule) => {
    const chips = vals.map(v =>
      `<span style="display:inline-block;padding:1px 6px;border-radius:8px;${toneStyle(rule)};margin:0 4px 0 0;font-size:12px;">${escapeHtml(v)}</span>`
    ).join("");
    html += `
      <div style="margin:2px 0;padding:0;white-space:normal;">
        <span style="display:inline-block;min-width:110px;color:#6b7280;font-size:12px;margin:0 6px 0 0;vertical-align:middle;">${escapeHtml(rule)}</span>
        <span style="display:inline-block;vertical-align:middle;">${chips}</span>
      </div>`;
  });
  html += "</div>";
  return html;
}

// ===== state =====
let PRESET = [];
let LAST_FILE = null;

// ===== init =====
init();
function init() { bindUI(); fetchPatterns(); setSaveVisible(false); }
function bindUI() {
  $("file").addEventListener("change", onFileChange);
  $("btn-scan").addEventListener("click", onScanClick);
  $("btn-save-redacted").addEventListener("click", onApplyClick);
}
async function fetchPatterns() {
  try {
    const res = await fetch(`${API_BASE}/patterns`, { cache: "no-store" });
    const j = await res.json();
    PRESET = Array.isArray(j?.patterns) ? j.patterns : [];
  } catch { PRESET = []; }
}

// ===== rules UI =====
function selectedRuleNames() {
  return Array.from(document.querySelectorAll('input[name="rule"]:checked')).map(el => el.value);
}
function selectedPatternsPayload() {
  const names = new Set(selectedRuleNames());
  if (!names.size || !PRESET.length) return null;
  const chosen = PRESET.filter(p => names.has(p.name));
  if (!chosen.length) return null;
  return { patterns: chosen };
}

// ===== file change =====
function onFileChange() {
  const f = $("file").files?.[0];
  LAST_FILE = f || null;

  $("redacted-preview").innerHTML = "";
  $("txt-raw").value = "";
  $("by-rule-ok").innerHTML = "";
  $("by-rule-ng").innerHTML = "";
  $("summary").textContent = "";
  $("status").textContent = "";
  $("file-info").textContent = "";
  setSaveVisible(false);

  if (!f) return;
  $("file-info").textContent = `${f.name} · ${(f.size/1024).toFixed(1)} KB · ${extOf(f.name).toUpperCase()}`;
}

// ===== actions =====
async function onScanClick() {
  const f = $("file").files?.[0];
  if (!f) return alert("파일을 선택하세요.");

  setSaveVisible(false);
  setStatus("스캔 중…");
  try {
    const data = await scanFile(f);
    const fullText = data?.extracted_text || "";
    const fileType = data?.file_type || (isPdfName(f.name) ? "pdf" : "xml");
    const matches = normalizeMatchesText(fullText, Array.isArray(data?.matches) ? data.matches : []);

    // 상단 미리보기 (타이트 칩)
    const html = PREVIEW_ONLY_MATCHES ? buildPreviewHtml_Grouped(fullText, matches, fileType) : "";
    $("redacted-preview").innerHTML = html;
    const rp = $("redacted-preview");
    rp.style.lineHeight = "1.15";
    rp.style.padding = "4px 0";
    rp.style.margin = "0";

    // 하단 원본 텍스트: 룰별 묶음
    const allGrouped = groupByRule(fullText, matches, { fileType, valid: "all", masked: false });
    const lines = [];
    allGrouped.forEach((vals, rule) => {
      lines.push(`${rule}`);
      vals.forEach(v => lines.push(`  ${v}`));
      lines.push("");
    });
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    $("txt-raw").value = lines.join("\n");

    // OK/NG 칩
    renderDetectedLists(matches, fileType);

    // 요약
    let total = 0; allGrouped.forEach(v => total += v.length);
    $("summary").textContent = `파일형식=${fileType || "-"} · 총 ${total}건`;

    setSaveVisible(true);
    setStatus("스캔 완료");
  } catch (e) {
    console.error(e);
    setSaveVisible(false);
    setStatus("");
    alert("스캔 중 오류: " + (e?.message || e));
  }
}

async function onApplyClick() {
  const f = $("file").files?.[0];
  if (!f) return alert("파일을 선택하세요.");
  setStatus("레닥션 중…");
  try {
    const { blob, filename } = await applyAndGetBlob(f);
    downloadBlob(blob, filename);

    if (/\.hwpx$/i.test(filename || "")) {
      if (HWPX_VIEWER_URL) {
        const url = URL.createObjectURL(blob);
        window.open(`${HWPX_VIEWER_URL}?file=${encodeURIComponent(url)}&v=${Date.now()}`, "_blank");
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
      }
    }

    setStatus("레닥션 완료. 파일이 저장되었습니다.");
  } catch (e) {
    console.error(e); setStatus("");
    alert("레닥션 중 오류: " + (e?.message || e));
  }
}

// ===== server calls =====
async function scanFile(file) {
  const fd = new FormData();
  fd.append("file", file);

  const pj = selectedPatternsPayload();
  if (pj) fd.append("patterns_json", JSON.stringify(pj));

  const url = isPdfName(file.name)
    ? `${API_BASE}/redactions/pdf/scan`
    : `${API_BASE}/redactions/xml/scan`;

  const res = await fetch(url, { method: "POST", body: fd, cache: "no-store" });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}
function _parseDownloadFilename(res) {
  const cd = res.headers.get("content-disposition") || "";
  const mStar = cd.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
  if (mStar) return decodeURIComponent(mStar[1].replace(/["']/g, ""));
  const m = cd.match(/filename\s*=\s*"([^"]+)"/i) || cd.match(/filename\s*=\s*([^;]+)/i);
  return m ? m[1].trim() : "";
}
async function applyAndGetBlob(file) {
  const fd = new FormData();
  fd.append("file", file);

  let url = "";
  if (isPdfName(file.name)) {
    fd.append("mode", "auto_all");
    fd.append("fill", "black");
    const pj = selectedPatternsPayload();
    if (pj) fd.append("patterns_json", JSON.stringify(pj));
    url = `${API_BASE}/redactions/apply`;
  } else if (isXmlDoc(file.name)) {
    url = `${API_BASE}/redactions/xml/apply`;
  } else {
    throw new Error("이 형식은 레닥션 적용을 지원하지 않습니다.");
  }

  const res = await fetch(url, { method: "POST", body: fd, cache: "no-store" });
  if (!res.ok) throw new Error(await res.text());

  const blob = await res.blob();
  const filename = _parseDownloadFilename(res) || `${file.name.replace(/\.[^.]+$/, "")}.redacted.${extOf(file.name)}`;
  return { blob, filename };
}

// ===== chips list (하단 위젯) =====
function renderDetectedLists(matches, fileType) {
  let ok, ng;
  if (fileType === "pdf") {
    ok = matches.filter(m => m.valid === true && Number.isFinite(m.page));
    ng = matches.filter(m => !(m.valid === true && Number.isFinite(m.page)));
  } else {
    ok = matches.filter(m => m.valid === true);
    ng = matches.filter(m => m.valid === false);
  }
  renderRuleChips($("by-rule-ok"), ok, false);
  renderRuleChips($("by-rule-ng"), ng, true);
}
function renderRuleChips(container, list, isNG=false) {
  const by = new Map();
  (list || []).forEach(m => {
    const k = m.rule || "unknown";
    const arr = by.get(k) || [];
    arr.push(m);
    by.set(k, arr);
  });
  if (!list.length) {
    container.innerHTML = `<div style="font-size:12px;color:#6b7280">없음</div>`;
    return;
  }
  const sections = [];
  by.forEach((arr, rule) => {
    const seen = new Set();
    const chips = [];
    arr.forEach(m => {
      const raw = (m.value || "").trim();
      if (!raw) return;
      const key = `${rule}:${raw}`;
      if (seen.has(key)) return;
      seen.add(key);
      const extra = isNG ? "outline:1px solid #fca5a5;" : "";
      chips.push(`<span style="display:inline-block;padding:2px 8px;border-radius:9999px;${toneStyle(rule)};${extra}margin:2px 6px 2px 0;font-size:12px;">${escapeHtml(raw)}</span>`);
    });
    sections.push(`
      <div style="margin:4px 0 6px 0;line-height:1.15;">
        <div style="font-size:12px;color:#6b7280;margin:0 0 2px 0;">${escapeHtml(rule)}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:flex-start;">${chips.join("")}</div>
      </div>
    `);
  });
  container.innerHTML = sections.join("");
}

// ===== status =====
function setStatus(msg) { $("status").textContent = msg || ""; }
