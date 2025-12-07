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
    const r = await fetch(`${API_BASE()}/text/ner`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    })
    if (r.ok) {
      const j = await r.json()
      const n = normalizeNerItems(j)
      if (n.items.length) return n
    }
  } catch {}
  // 2) /text/detect (run_ner)
  const r2 = await fetch(`${API_BASE()}/text/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text,
      options: { run_regex: false, run_ner: true },
    }),
  })
  if (!r2.ok) return { items: [] }
  const j2 = await r2.json()
  return normalizeNerItems(j2, j2.text || text || '')
}

// NER 테이블
function renderNerTable(ner) {
  const rows = $('#ner-rows')
  const sum = $('#ner-summary')
  const allow = new Set()
  $('#ner-show-ps')?.checked !== false && allow.add('PS')
  $('#ner-show-lc')?.checked !== false && allow.add('LC')
  $('#ner-show-og')?.checked !== false && allow.add('OG')

  const items = (ner.items || []).filter((it) =>
    allow.has((it.label || '').toUpperCase())
  )
  if (rows) rows.innerHTML = ''
  for (const it of items) {
    const tr = document.createElement('tr')
    tr.className = 'border-b align-top'
    tr.innerHTML = `
      <td class="py-2 px-2 font-mono">${esc(it.label)}</td>
      <td class="py-2 px-2 font-mono">${esc(it.text)}</td>
      <td class="py-2 px-2 font-mono">${
        typeof it.score === 'number' ? it.score.toFixed(2) : '-'
      }</td>
      <td class="py-2 px-2 font-mono">${it.start}-${it.end}</td>`
    rows?.appendChild(tr)
  }
  badge('#ner-badge', items.length)
  if (sum) {
    const counts = {}
    for (const it of items) counts[it.label] = (counts[it.label] || 0) + 1
    sum.textContent = `검출: ${
      Object.keys(counts).length
        ? Object.entries(counts)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ')
        : '없음'
    }`
  }
}

// 상태
function setStatus(msg) {
  const el = $('#status')
  if (el) el.textContent = msg || ''
}

// 스캔 버튼
$('#btn-scan')?.addEventListener('click', async () => {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  const ext = (f.name.split('.').pop() || '').toLowerCase()
  __lastRedactedName = f.name
    ? f.name.replace(/\.[^.]+$/, `_redacted.${ext}`)
    : `redacted.${ext}`

  setStatus('텍스트 추출 및 매칭 중...')
  const fd = new FormData()
  fd.append('file', f)

  $('#match-result-block')?.classList.remove('hidden')
  $('#ner-result-block')?.classList.remove('hidden')

  try {
    // 1) 텍스트 추출
    const r1 = await fetch(`${API_BASE()}/text/extract`, {
      method: 'POST',
      body: fd,
    })
    if (!r1.ok)
      throw new Error(`텍스트 추출 실패 (${r1.status})\n${await r1.text()}`)
    const { full_text: text = '' } = await r1.json()

    // 프리뷰
    $('#text-preview-block')?.classList.remove('hidden')
    const ta = $('#txt-out')
    if (ta) ta.value = text || '(본문 텍스트가 비어 있습니다.)'

    // 2) 정규식 매칭
    const rules = selectedRuleNames()
    const r2 = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, rules, normalize: true }),
    })
    if (!r2.ok) throw new Error(`매칭 실패 (${r2.status})\n${await r2.text()}`)
    renderRegexResults(await r2.json())
    setOpen('match', true)

    // 3) NER (스마트 호출)
    const ner = await requestNerSmart(text)
    renderNerTable(ner)
    ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) =>
      $(sel)?.addEventListener('change', () => renderNerTable(ner))
    )
    setOpen('ner', true)

    setStatus(`스캔 완료 (${ext.toUpperCase()} 처리)`)

    // 4) 레닥션 파일 생성
    setStatus('레닥션 파일 생성 중...')
    const r4 = await fetch(`${API_BASE()}/redact/file`, {
      method: 'POST',
      body: fd,
    })
    if (!r4.ok) throw new Error(`레닥션 실패 (${r4.status})`)
    const blob = await r4.blob()
    const ctype = r4.headers.get('Content-Type') || 'application/octet-stream'
    __lastRedactedBlob = new Blob([blob], { type: ctype })

    if (ctype.includes('pdf')) {
      setOpen('pdf', true)
      await renderRedactedPdfPreview(__lastRedactedBlob)
    } else {
      setOpen('pdf', false)
    }

    const btn = $('#btn-save-redacted')
    if (btn) {
      btn.classList.remove('hidden')
      btn.disabled = false
    }
    setStatus('레닥션 완료 — 다운로드 가능')
  } catch (e) {
    console.error(e)
    setStatus(`오류: ${e.message || e}`)
  }
})

// 다운로드
$('#btn-save-redacted')?.addEventListener('click', () => {
  if (!__lastRedactedBlob) return alert('레닥션된 파일이 없습니다.')
  const url = URL.createObjectURL(__lastRedactedBlob)
  const a = document.createElement('a')
  a.href = url
  a.download = __lastRedactedName || 'redacted_file'
  a.click()
  URL.revokeObjectURL(url)
})

// 초기화
document.addEventListener('DOMContentLoaded', () => {
  loadRules()
  setupDropZone()
})