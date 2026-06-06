const API_BASE = () => window.API_BASE || 'http://127.0.0.1:8000'

const $ = (sel) => document.querySelector(sel)
const $$ = (sel) => Array.from(document.querySelectorAll(sel))

/** ---------- Persistence (localStorage) ---------- */
const PREFS_KEY = 'eclipso_ui_prefs_v1'

function loadPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY)
    if (!raw) return {}
    const obj = JSON.parse(raw)
    return obj && typeof obj === 'object' ? obj : {}
  } catch {
    return {}
  }
}

function savePrefs(patch) {
  try {
    const cur = loadPrefs()
    const next = { ...(cur || {}), ...(patch || {}) }
    localStorage.setItem(PREFS_KEY, JSON.stringify(next))
  } catch {
    // ignore
  }
}

/** ---------- State ---------- */
let state = {
  file: null,
  ext: '',
  t0: null,
  timings: null,

  extractedText: '',
  markdown: '',
  normalizedText: '',
  pages: [],
  pageIndex: 0,

  rules: [],
  nerLabels: [],

  matchData: null,
  nerItems: [],

  detections: [],
  detectionById: new Map(),

  selectedId: null,

  filters: { q: '', seg: 'all' },

  ui: {},

  // 부분 마스킹 정책(레닥션에만 사용)
  // 예: { ps: "keep_first_char", rrn: "keep_birth6", phone: "keep_first_group" }
  maskingPolicy: {},
}

// load persisted prefs early (so loadRules can reflect initial button state)
;(function hydratePrefsEarly() {
  const p = loadPrefs()
  if (p && typeof p === 'object') {
    if (p.maskingPolicy && typeof p.maskingPolicy === 'object')
      state.maskingPolicy = { ...p.maskingPolicy }
  }
})()

/** ---------- Safe DOM helpers (핵심: null 방지) ---------- */
const byId = (id) => document.getElementById(id)

function safeText(id, v) {
  const el = byId(id)
  if (!el) return
  el.textContent = String(v ?? '')
}

function safeHtml(id, html) {
  const el = byId(id)
  if (!el) return
  el.innerHTML = String(html ?? '')
}

function safeShow(id, show = true) {
  const el = byId(id)
  if (!el) return
  el.classList.toggle('hidden', !show)
}

function safeClassRemove(id, cls) {
  const el = byId(id)
  if (!el) return
  el.classList.remove(cls)
}

function safeWidthPct(id, pct) {
  const el = byId(id)
  if (!el) return
  el.style.width = pct
}

function safeToggleHidden(id) {
  const el = byId(id)
  if (!el) return
  el.classList.toggle('hidden')
}

/** ---------- Utils ---------- */
const escHtml = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

function setStatus(msg) {
  const el = $('#status')
  if (el) el.textContent = msg || ''
}

function setStatusSub(msg) {
  const el = $('#status-sub')
  if (el) el.textContent = msg || ''
}

function setProgress(pct, label = '', opts = {}) {
  const forceShow = !!opts.forceShow
  const p = Number.isFinite(+pct) ? Math.max(0, Math.min(100, +pct)) : 0
  safeShow('progress-wrap', forceShow || p > 0)
  safeWidthPct('progress-bar', `${p}%`)
  safeText('progress-pct', `${Math.round(p)}%`)
  safeText('progress-label', label || '-')
}

function resetProgress() {
  setProgress(0, '-', { forceShow: false })
  setStatusSub('')
}

function safeJson(v) {
  try {
    return JSON.stringify(v ?? null)
  } catch {
    return null
  }
}

function parseContentDispositionFilename(cd) {
  // supports: filename="a.pdf" / filename*=UTF-8''%E3%85...
  if (!cd) return null
  const s = String(cd)
  const mStar = s.match(/filename\*\s*=\s*([^;]+)/i)
  if (mStar) {
    const v = mStar[1].trim()
    const m = v.match(/utf-8''(.+)/i)
    if (m) {
      try {
        return decodeURIComponent(m[1].replace(/^"|"$/g, ''))
      } catch {
        return m[1].replace(/^"|"$/g, '')
      }
    }
    return v.replace(/^"|"$/g, '')
  }
  const m = s.match(/filename\s*=\s*([^;]+)/i)
  if (!m) return null
  return m[1].trim().replace(/^"|"$/g, '')
}

function buildRedactedFallbackName(original) {
  const name = String(original || 'redacted')
  const dot = name.lastIndexOf('.')
  if (dot <= 0) return `${name}_redacted`
  return `${name.slice(0, dot)}_redacted${name.slice(dot)}`
}

function lockInputs(on) {
  $('#btn-scan') && ($('#btn-scan').disabled = !!on)
  $('#file') && ($('#file').disabled = !!on)
  $$('input[name="rule"]').forEach((el) => (el.disabled = !!on))
  ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) => {
    const el = $(sel)
    if (el) el.disabled = !!on
  })
}

function setPages(pages) {
  const arr = Array.isArray(pages)
    ? pages.filter((x) => typeof x === 'string')
    : []
  state.pages = arr.length ? arr : ['']
  state.pageIndex = 0
  updatePageControls()
}

function splitMarkdownToPages(md, maxChars = 3200) {
  const s = String(md || '').replace(/\r\n/g, '\n')
  if (!s.trim()) return ['']
  const hardMax = Math.max(800, Number(maxChars) || 3200)
  if (s.length <= hardMax) return [s]

  const out = []
  let i = 0
  while (i < s.length) {
    const end = Math.min(s.length, i + hardMax)
    if (end >= s.length) {
      out.push(s.slice(i))
      break
    }

    // 가능한 한 "문단 경계"에서 끊기
    let cut = s.lastIndexOf('\n\n', end)
    if (cut < i + 600) cut = s.lastIndexOf('\n', end)
    if (cut < i + 300) cut = end

    out.push(s.slice(i, cut).trimEnd())
    i = cut
  }

  return out.filter((x) => typeof x === 'string' && x.trim().length > 0)
}

function buildPagesFromExtractData(extractData, fallbackMd) {
  const ed = extractData && typeof extractData === 'object' ? extractData : {}

  // 0) 서버가 viewer-safe 페이지 배열을 주면 최우선 사용(base64 이미지 split 방지)
  const pv = Array.isArray(ed.pages_view) ? ed.pages_view : []
  if (pv.length) {
    return pv.map((x) => String(x || '')).filter((x) => x.trim().length > 0)
  }

  // 1) PDF 등: pages_md가 있으면 "진짜 페이지"로 사용
  const pmd = Array.isArray(ed.pages_md) ? ed.pages_md : []
  if (pmd.length) {
    return pmd
      .slice()
      .sort((a, b) => Number(a?.page || 0) - Number(b?.page || 0))
      .map((p) => String(p?.markdown || ''))
      .filter((x) => x.trim().length > 0)
  }

  // 2) 모듈이 pages를 여러 개 제공하는 경우 (PDF의 경우 페이지별 텍스트)
  const p = Array.isArray(ed.pages) ? ed.pages : []
  if (p.length >= 1) {
    const pages = p
      .slice()
      .sort((a, b) => Number(a?.page || 0) - Number(b?.page || 0))
      .map((it) => {
        const text = String(it?.text || '')
        // 페이지 헤더 추가 (페이지 번호 표시)
        const pageNum = it?.page || 0
        if (text.trim()) {
          return `**📄 페이지 ${pageNum}**\n\n${text}`
        }
        return ''
      })
    const filtered = pages.filter((x) => x.trim().length > 0)
    if (filtered.length > 0) {
      return filtered
    }
  }

  // 3) 그 외(대부분 OLE/XML): markdown/full_text를 "가상 페이지"로 분할
  return splitMarkdownToPages(fallbackMd, 3200)
}

function updatePageControls() {
  const total = Math.max(1, state.pages.length || 1)
  const idx = Math.max(0, Math.min(total - 1, state.pageIndex || 0))
  state.pageIndex = idx

  const ind = $('#doc-page-indicator')
  if (ind) ind.textContent = `${idx + 1} / ${total}`

  const prev = $('#btn-page-prev')
  const next = $('#btn-page-next')
  if (prev) prev.disabled = idx <= 0
  if (next) next.disabled = idx >= total - 1
}

function clearViewerSelection() {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  viewer.querySelectorAll('.pii-box[data-selected="1"]').forEach((el) => {
    el.removeAttribute('data-selected')
    // 빨간색 강조 스타일 제거
    el.style.outline = ''
    el.style.outlineOffset = ''
    el.style.backgroundColor = ''
    el.style.boxShadow = ''
  })
}

/**
 * detection이 포함된 페이지 인덱스를 찾아 반환 (없으면 -1)
 */
function findPageForDetection(detection) {
  if (!detection || !state.pages || state.pages.length <= 1) return -1

  const text = String(detection.text || '').trim()
  if (!text || text.length < 2) return -1

  // 각 페이지에서 텍스트 검색
  for (let i = 0; i < state.pages.length; i++) {
    const pageContent = String(state.pages[i] || '')
    if (pageContent.includes(text)) {
      return i
    }
  }

  // 정확한 매칭 실패 시 부분 매칭 시도 (공백/줄바꿈 무시)
  const normalizedText = text.replace(/\s+/g, '')
  for (let i = 0; i < state.pages.length; i++) {
    const normalizedPage = String(state.pages[i] || '').replace(/\s+/g, '')
    if (normalizedPage.includes(normalizedText)) {
      return i
    }
  }

  return -1
}

/**
 * detection이 있는 페이지로 이동 후 선택 적용
 */
function navigateToAndSelectDetection(id) {
  const detection = state.detectionById?.get(id)
  if (!detection) return

  const pageIdx = findPageForDetection(detection)

  if (pageIdx >= 0 && pageIdx !== state.pageIndex) {
    // 다른 페이지에 있으면 이동
    state.pageIndex = pageIdx
    state.selectedId = id
    renderCurrentPage()

    // 페이지 렌더링 후 선택 적용 (약간의 딜레이)
    setTimeout(() => {
      clearViewerSelection()
      applyViewerSelection(id)
    }, 50)
  } else {
    // 같은 페이지면 바로 선택
    clearViewerSelection()
    applyViewerSelection(id)
  }
}

function applyViewerSelection(id) {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  const spans = viewer.querySelectorAll(`.pii-box[data-id="${CSS.escape(id)}"]`)
  spans.forEach((el) => {
    el.setAttribute('data-selected', '1')
    // 빨간색 강조 + 애니메이션 효과
    el.style.outline = '3px solid #ef4444'
    el.style.outlineOffset = '2px'
    el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)'
    el.style.boxShadow = '0 0 12px rgba(239, 68, 68, 0.5)'
    el.style.borderRadius = '4px'
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  })
}

/** ---------- Dropzone ---------- */
function setupDropZone() {
  const dz = $('#dropzone'),
    input = $('#file'),
    nameEl = $('#file-name')
  if (!dz || !input) return

  let depth = 0

  const setActive = (on) => {
    dz.classList.toggle('ring-2', on)
    dz.style.setProperty('--tw-ring-color', on ? '#4f46e5' : '')
    dz.style.backgroundColor = on ? '#fafafa' : ''
  }

  const showName = (f) => {
    if (nameEl) nameEl.textContent = f ? f.name : ''
  }

  ;['dragover', 'drop'].forEach((ev) =>
    window.addEventListener(ev, (e) => e.preventDefault())
  )

  dz.addEventListener('dragenter', (e) => {
    e.preventDefault()
    depth++
    setActive(true)
    e.dataTransfer && (e.dataTransfer.dropEffect = 'copy')
  })
  dz.addEventListener('dragover', (e) => {
    e.preventDefault()
    e.dataTransfer && (e.dataTransfer.dropEffect = 'copy')
  })
  ;['dragleave', 'dragend'].forEach((ev) =>
    dz.addEventListener(ev, (e) => {
      e.preventDefault()
      depth = Math.max(0, depth - 1)
      if (!depth) setActive(false)
    })
  )

  dz.addEventListener('drop', (e) => {
    e.preventDefault()
    depth = 0
    setActive(false)
    const dt = e.dataTransfer
    let file = (dt.files && dt.files[0]) || null
    if (!file && dt.items) {
      for (const it of dt.items) {
        if (it.kind === 'file') {
          const f = it.getAsFile()
          if (f) {
            file = f
            break
          }
        }
      }
    }
    if (!file) return
    const repl = new DataTransfer()
    repl.items.add(file)
    input.files = repl.files
    input.dispatchEvent(new Event('change', { bubbles: true }))
    showName(file)
    setStatus('파일 선택됨 · 탐지 실행')
  })

  input.addEventListener('change', (e) => showName(e.target.files?.[0] || null))
}

/** ---------- Rules & Policies ---------- */
async function loadRules() {
  try {
    const r = await fetch(`${API_BASE()}/text/rules`)
    if (!r.ok) throw 0
    const rules = await r.json()
    const box = $('#rules-container')
    if (!box) return
    box.innerHTML = ''

    const prefs = loadPrefs()
    const persistedSelectedRules = Array.isArray(prefs?.selectedRules)
      ? prefs.selectedRules.map((x) => String(x))
      : null

    const isRulePartialSupported = (ruleName) => {
      const r = String(ruleName || '').toLowerCase()
      return (
        r.includes('rrn') ||
        r.includes('fgn') ||
        r.includes('card') ||
        r.includes('phone_mobile') ||
        r.includes('phone_city') ||
        r.includes('phone')
      )
    }

    const getRuleKey = (ruleName) => {
      const r = String(ruleName || '').toLowerCase()
      if (r.includes('rrn')) return 'rrn'
      if (r.includes('fgn')) return 'fgn'
      if (r.includes('phone')) return 'phone'
      if (r.includes('card')) return 'card'
      return r
    }

    const isRulePartialOn = (ruleName) => {
      const key = getRuleKey(ruleName)
      return !!state.maskingPolicy?.[key]
    }

    const setRulePartialOn = (ruleName, on) => {
      const key = getRuleKey(ruleName)
      state.maskingPolicy = state.maskingPolicy || {}
      if (!on) delete state.maskingPolicy[key]
      else {
        if (key === 'rrn' || key === 'fgn')
          state.maskingPolicy[key] = 'keep_birth6'
        else if (key === 'phone') state.maskingPolicy[key] = 'keep_first_group'
        else if (key === 'card') state.maskingPolicy[key] = 'keep_first4_last4'
        else state.maskingPolicy[key] = 'partial'
      }
      savePrefs({ maskingPolicy: state.maskingPolicy })
    }

    const applyRuleBtnStyle = (btn, on) => {
      if (!btn) return
      btn.textContent = on ? '부분' : '전체'
      btn.className =
        'text-[11px] px-2 py-0.5 rounded-full border transition ' +
        (on
          ? 'border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100'
          : 'border-gray-200 bg-gray-50 text-gray-600 hover:bg-gray-100')
    }

    for (const rule of rules) {
      const wrap = document.createElement('div')
      wrap.className = 'flex items-center justify-between gap-2'

      const el = document.createElement('label')
      el.className =
        'flex items-center gap-2 cursor-pointer hover:text-indigo-600 transition min-w-0'
      const checkedAttr =
        persistedSelectedRules && persistedSelectedRules.length
          ? persistedSelectedRules.includes(String(rule))
            ? 'checked'
            : ''
          : 'checked'
      const ruleLabel = ruleToKind(rule)
      el.innerHTML = `<input type="checkbox" name="rule" value="${escHtml(
        rule
      )}" ${checkedAttr} class="rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500"><span class="truncate" title="${escHtml(
        String(rule || '')
      )}">${escHtml(ruleLabel)}</span>`

      wrap.appendChild(el)

      if (isRulePartialSupported(rule)) {
        const btn = document.createElement('button')
        btn.type = 'button'
        btn.title = '부분 마스킹 (전체/부분)'

        const key = getRuleKey(rule)
        applyRuleBtnStyle(btn, isRulePartialOn(rule))
        btn.addEventListener('click', (e) => {
          e.preventDefault()
          e.stopPropagation()

          const next = !isRulePartialOn(rule)
          setRulePartialOn(rule, next)
          applyRuleBtnStyle(btn, next)
        })
        wrap.appendChild(btn)
      }

      box.appendChild(wrap)
    }

    // persist rule checkbox changes
    box
      .querySelectorAll('input[type="checkbox"][name="rule"]')
      .forEach((cb) => {
        cb.addEventListener('change', () => {
          const selected = $$('input[name="rule"]:checked').map((x) => x.value)
          savePrefs({ selectedRules: selected })
        })
      })
  } catch {
    // 기본값 유지
  }
}

function selectedRuleNames() {
  return $$('input[name="rule"]:checked').map((el) => el.value)
}

function selectedNerLabels() {
  const labels = []
  $('#ner-show-ps')?.checked !== false && labels.push('PS')
  $('#ner-show-lc')?.checked !== false && labels.push('LC')
  $('#ner-show-og')?.checked !== false && labels.push('OG')
  return labels
}

function setupPsMaskModeButton() {
  const btn = document.getElementById('btn-ps-mask-mode')
  if (!btn) return

  const mode = () => {
    const ps = String(state.maskingPolicy?.ps || '')
    const two = String(state.maskingPolicy?.ps_twochar || '')
    if (ps !== 'keep_first_char') return 'full'
    if (two === 'mask_full') return 'keep_first_char'
    return 'keep_first_char'
  }

  const apply = () => {
    const m = mode()
    btn.textContent = m === 'full' ? '전체' : '부분'
    btn.title =
      m === 'full'
        ? '이름(PS) 마스킹: 전체'
        : m === 'keep_first_char'
        ? '이름(PS) 마스킹: 성만 남김'
        : '이름(PS) 마스킹: 성만 남김'
    btn.className =
      'ml-auto text-[11px] px-2 py-0.5 rounded-full border transition ' +
      (m !== 'full'
        ? 'border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100'
        : 'border-gray-200 bg-gray-50 text-gray-600 hover:bg-gray-100')
  }

  btn.addEventListener('click', (e) => {
    e.preventDefault()
    state.maskingPolicy = state.maskingPolicy || {}
    const m = mode()
    if (m === 'full') {
      state.maskingPolicy.ps = 'keep_first_char'
      delete state.maskingPolicy.ps_twochar
    } else {
      delete state.maskingPolicy.ps
      delete state.maskingPolicy.ps_twochar
    }
    savePrefs({ maskingPolicy: state.maskingPolicy })
    apply()
  })

  apply()
}

/** ---------- Markdown fallback ---------- */
function fallbackMarkdownFromText(text) {
  // NOTE:
  // marked는 "라인 시작 공백 4개"를 코드블록으로 렌더링한다.
  // 텍스트 추출 결과(특히 HWP)는 들여쓰기가 많아서, 하이라이트용 <span>이
  // 코드블록 내부 "문자"로 보이는 문제가 생긴다.
  // 따라서 라인 시작 공백은 &nbsp;로 바꿔 코드블록 해석을 막는다.
  const s = escHtml(String(text || ''))
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
  return s.replace(/^( +)/gm, (m, sp) => '&nbsp;'.repeat(sp.length))
}

/** ---------- Match / NER ---------- */
function normalizeNerItems(raw) {
  if (!raw) return { items: [] }
  if (Array.isArray(raw.entities)) return { items: raw.entities }
  if (Array.isArray(raw.items)) return { items: raw.items }
  if (Array.isArray(raw)) return { items: raw }
  return { items: [] }
}

async function requestNerSmart(text, exclude_spans, labels_override = null) {
  const labels =
    Array.isArray(labels_override) && labels_override.length
      ? labels_override
      : selectedNerLabels()

  const bodyObj = {
    text: String(text || ''),
    labels,
    exclude_spans: Array.isArray(exclude_spans) ? exclude_spans : [],
    debug: false,
  }

  try {
    const r2 = await fetch(`${API_BASE()}/ner/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bodyObj),
    })
    if (!r2.ok) return { items: [] }
    const j2 = await r2.json()
    return normalizeNerItems(j2)
  } catch {
    return { items: [] }
  }
}

function filterMatchByRules(matchData, rules) {
  const allow = new Set((rules || []).map((r) => String(r).toLowerCase()))
  const items = Array.isArray(matchData?.items) ? matchData.items : []
  const kept = allow.size
    ? items.filter((it) => allow.has(String(it.rule || '').toLowerCase()))
    : items
  const counts = {}
  for (const it of kept) {
    if (it?.valid) counts[it.rule] = (counts[it.rule] || 0) + 1
  }
  return { ...matchData, items: kept, counts }
}

function buildExcludeSpansFromMatch(matchData) {
  const items = Array.isArray(matchData?.items) ? matchData.items : []
  const spans = []
  for (const it of items) {
    if (it?.valid === false) continue
    const s = Number(it.start ?? -1)
    const e = Number(it.end ?? -1)
    if (!(e > s)) continue
    spans.push({ start: s, end: e })
  }
  return spans
}

/** ---------- Kind mapping ---------- */
function ruleToKind(rule) {
  const r = String(rule || '').toLowerCase()
  if (!r) return 'UNKNOWN'
  if (r.includes('rrn')) return '주민등록번호'
  if (r.includes('fgn')) return '외국인등록번호'
  if (r.includes('card')) return '카드번호'
  if (r.includes('email')) return '이메일'
  if (r.includes('passport')) return '여권번호'
  if (r.includes('driver')) return '운전면허번호'
  if (r.includes('phone_mobile') || r.includes('mobile')) return '휴대전화'
  if (r.includes('phone_city') || r.includes('city')) return '지역전화'
  if (r.includes('phone') || r.includes('tel')) return '전화번호'
  return String(rule)
}

/** ---------- Detections: build + render ---------- */
function makeId() {
  return (
    'd_' + Math.random().toString(16).slice(2) + '_' + Date.now().toString(16)
  )
}

function buildDetections(matchData, nerItems, nerAllowLabels, fullText) {
  const out = []
  const allow = new Set(
    (nerAllowLabels || []).map((x) => String(x).toUpperCase())
  )
  const mdItems = Array.isArray(matchData?.items) ? matchData.items : []
  const ner = Array.isArray(nerItems) ? nerItems : []

  const isHangul = (ch) => /[가-힣]/.test(String(ch || ''))

  for (const it of mdItems) {
    const id = makeId()
    const kind = ruleToKind(it?.rule)
    const val = String(it?.value ?? '')
    out.push({
      id,
      source: 'regex',
      kind,
      label: null,
      rule: it?.rule ?? null,
      text: val,
      start: Number.isFinite(+it?.start) ? +it.start : null,
      end: Number.isFinite(+it?.end) ? +it.end : null,
      valid: it?.valid !== false,
      fail_reason: it?.fail_reason || null,
      score: null,
    })
  }

  for (const it of ner) {
    const lab = String(it?.label || '').toUpperCase()
    if (!allow.has(lab)) continue
    const id = makeId()

    let s0 = Number.isFinite(+it?.start) ? +it.start : null
    let e0 = Number.isFinite(+it?.end) ? +it.end : null
    let txt = String(it?.text ?? '')

    // PS는 NER가 1글자(예: "남")만 찍는 경우가 있어,
    // full_text에서 주변 한글 토큰으로 확장해 "실제 레닥션 범위"와 맞춘다.
    if (
      lab === 'PS' &&
      typeof fullText === 'string' &&
      fullText &&
      Number.isFinite(s0) &&
      Number.isFinite(e0) &&
      e0 > s0
    ) {
      const n = fullText.length
      let a = Math.max(0, Math.min(n, s0))
      let b = Math.max(0, Math.min(n, e0))

      // 왼쪽 확장
      while (a > 0 && isHangul(fullText[a - 1])) a--
      // 오른쪽 확장
      while (b < n && isHangul(fullText[b])) b++

      // 너무 길게 확장되는 경우는 오탐 가능성이 있어 제한
      if (b > a && b - a <= 12) {
        const ext = fullText.slice(a, b)
        if (ext && ext.length >= txt.length) {
          txt = ext
          s0 = a
          e0 = b
        }
      }
    }

    out.push({
      id,
      source: 'ner',
      kind: null,
      label: lab,
      rule: null,
      text: txt,
      start: s0,
      end: e0,
      valid: true,
      score: typeof it?.score === 'number' ? it.score : null,
    })
  }

  out.sort((a, b) => {
    const as = a.start ?? 1e18
    const bs = b.start ?? 1e18
    if (as !== bs) return as - bs
    const ae = a.end ?? 1e18
    const be = b.end ?? 1e18
    return ae - be
  })

  return out
}

function injectBoxesIntoMarkdown(md, detections) {
  let s = String(md || '')
  if (!s.trim() || !detections?.length) return s
  if (s.includes('<!--ECLIPSO_PII-->')) return s

  const escapeRegExp = (str) =>
    String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

  // placeholder(__TAG_n__)는 유지하면서 텍스트만 escape (XSS 방지 + 태그 복원 유지)
  const escHtmlKeepPlaceholders = (text) =>
    String(text)
      .split(/(__TAG_\d+__)/g)
      .map((part) => (/^__TAG_\d+__$/.test(part) ? part : escHtml(part)))
      .join('')

  const findNeedleFrom = (hay, needle, startAt) => {
    const start = Math.max(0, startAt || 0)
    let idx = hay.indexOf(needle, start)
    if (idx >= 0) return { idx, len: needle.length }

    // 표/셀 등에서 "중간 줄바꿈/공백/<br>"로 끊어진 케이스 보정
    if (!needle || needle.length < 4) return null

    // 문자 사이에 짧은 공백/제로폭/태그 placeholder가 끼는 것을 허용
    const gap = '(?:[\\s\\u200b\\u200c\\u200d\\ufeff]{0,2}|__TAG_\\d+__){0,2}'
    const pat = Array.from(needle)
      .map((ch) => escapeRegExp(ch))
      .join(gap)
    let re
    try {
      re = new RegExp(pat, 'g')
    } catch {
      return null
    }

    re.lastIndex = start
    const m = re.exec(hay)
    if (!m || typeof m.index !== 'number') return null

    const raw = String(m[0] || '')
    const maxExtra = Math.min(24, Math.max(6, Math.floor(needle.length * 0.6)))
    if (raw.length > needle.length + maxExtra) return null

    return { idx: m.index, len: raw.length }
  }

  const tags = []
  s = s.replace(/<[^>]+>/g, (match) => {
    const placeholder = `__TAG_${tags.length}__`
    tags.push(match)
    return placeholder
  })

  const overlaps = (a0, a1, b0, b1) => Math.min(a1, b1) - Math.max(a0, b0) > 0

  const occupied = []
  const reps = []

  // 길이가 긴(=더 구체적인) 텍스트부터 먼저 매칭해서, 중첩/겹침을 최소화한다.
  const dets = Array.isArray(detections) ? detections.slice() : []
  dets.sort((a, b) => {
    const av = a?.valid === false ? 0 : 1
    const bv = b?.valid === false ? 0 : 1
    if (av !== bv) return bv - av
    const asrc = a?.source === 'regex' ? 0 : 1
    const bsrc = b?.source === 'regex' ? 0 : 1
    if (asrc !== bsrc) return asrc - bsrc
    const al = String(a?.text || '').trim().length
    const bl = String(b?.text || '').trim().length
    return bl - al
  })

  for (const d of dets) {
    const needle = String(d?.text || '').trim()
    if (!needle) continue
    if (needle.length < 2) {
      // PS는 1글자(예: "남")도 표시되게 허용
      if (
        !(d?.source === 'ner' && String(d?.label || '').toUpperCase() === 'PS')
      )
        continue
    }
    if (/^[A-Za-z]$/.test(needle)) continue

    let startAt = 0
    let found = null
    while (true) {
      const f = findNeedleFrom(s, needle, startAt)
      if (!f) break
      const a0 = f.idx
      const a1 = f.idx + f.len
      if (!occupied.some(([b0, b1]) => overlaps(a0, a1, b0, b1))) {
        found = f
        break
      }
      startAt = f.idx + 1
    }
    if (!found) continue

    const idx = found.idx
    const matchLen = found.len
    occupied.push([idx, idx + matchLen])

    const tag =
      d.source === 'regex'
        ? `REGEX·${d.kind || 'UNK'}`
        : `NER·${d.label || 'UNK'}`

    const baseCls =
      'pii-box inline-flex flex-wrap items-center gap-1 px-[2px] rounded-md cursor-pointer align-baseline'
    const clsOk =
      'bg-indigo-500/10 shadow-[inset_0_0_0_2px_rgba(79,70,229,0.95)]'
    const clsFail =
      'bg-gray-500/10 shadow-[inset_0_0_0_2px_rgba(107,114,128,0.95)] opacity-70'
    const cls = `${baseCls} ${d.valid ? clsOk : clsFail}`

    const attrs = [
      `class="${cls}"`,
      `data-id="${escHtml(d.id)}"`,
      `data-source="${escHtml(d.source)}"`,
      d.kind ? `data-kind="${escHtml(d.kind)}"` : '',
      d.label ? `data-label="${escHtml(d.label)}"` : '',
      `data-valid="${d.valid ? '1' : '0'}"`,
      `data-tag="${escHtml(tag)}"`,
    ]
      .filter(Boolean)
      .join(' ')

    const pill = `<span class="inline-block px-1.5 py-0.5 rounded-full text-[10px] font-bold whitespace-nowrap bg-gray-900/5 text-gray-900">${escHtml(
      tag
    )}</span>`

    reps.push({ idx, len: matchLen, attrs, pill })
  }

  // 뒤에서부터 치환하면 인덱스가 깨지지 않는다.
  reps.sort((a, b) => (b.idx || 0) - (a.idx || 0))
  for (const r of reps) {
    const before = s.slice(0, r.idx)
    const mid = s.slice(r.idx, r.idx + r.len)
    const after = s.slice(r.idx + r.len)
    const wrapped = `<span ${r.attrs}>${escHtmlKeepPlaceholders(mid)}${
      r.pill
    }</span>`
    s = before + wrapped + after
  }

  tags.forEach((tag, i) => {
    s = s.replace(`__TAG_${i}__`, tag)
  })

  return `<!--ECLIPSO_PII-->${s}`
}

function filterDetectionsForViewer(detections) {
  const arr = Array.isArray(detections) ? detections.slice() : []
  if (!arr.length) return []

  const hasRange = (d) => Number.isFinite(+d?.start) && Number.isFinite(+d?.end)
  const overlap = (a, b) =>
    Math.min(a.end, b.end) - Math.max(a.start, b.start) > 0

  // 1) exact duplicate (same range+source+text) 제거
  const seen = new Set()
  const dedup = []
  for (const d of arr) {
    const k = `${d?.source || ''}|${d?.start ?? ''}|${d?.end ?? ''}|${String(
      d?.text ?? ''
    )}`
    if (seen.has(k)) continue
    seen.add(k)
    dedup.push(d)
  }

  // 2) viewer에서는 regex(valid) 우선, 그 위에 겹치는 NER은 제거(라벨 중첩 방지)
  const regexRanges = dedup
    .filter((d) => d?.source === 'regex' && d?.valid !== false && hasRange(d))
    .map((d) => ({ start: +d.start, end: +d.end }))

  const out = []
  for (const d of dedup) {
    if (d?.source === 'ner' && hasRange(d) && regexRanges.length) {
      const sp = { start: +d.start, end: +d.end }
      if (regexRanges.some((r) => overlap(r, sp))) continue
    }
    out.push(d)
  }

  // 3) 같은 타입끼리 완전 포함(contained)되는 경우 긴 것만 남김(중첩 라벨 방지)
  const withRange = out
    .filter(hasRange)
    .slice()
    .sort((a, b) => {
      const as = +a.start
      const bs = +b.start
      if (as !== bs) return as - bs
      const al = +a.end - +a.start || 0
      const bl = +b.end - +b.start || 0
      return bl - al
    })
  const kept = []
  for (const d of withRange) {
    const s = +d.start
    const e = +d.end
    const sameSource = (x) => (x?.source || '') === (d?.source || '')
    const contains = (x) => +x.start <= s && +x.end >= e
    if (kept.some((x) => sameSource(x) && contains(x))) continue
    kept.push(d)
  }

  const noRange = out.filter((d) => !hasRange(d))
  return kept.concat(noRange)
}

function renderMarkdownToViewer(md, detections) {
  const viewer = $('#doc-viewer')
  if (!viewer) return

  const detsForViewer = filterDetectionsForViewer(detections)
  const md2 = injectBoxesIntoMarkdown(
    normalizeTsvTablesToMarkdown(md),
    detsForViewer
  )

  let html = ''
  try {
    marked.setOptions({ gfm: true, breaks: true })
    html = marked.parse(md2)
  } catch {
    html = `<pre>${escHtml(md2)}</pre>`
  }

  const clean = DOMPurify.sanitize(html, {
    ADD_TAGS: [
      'span',
      'img',
      'table',
      'thead',
      'tbody',
      'tr',
      'th',
      'td',
      'colgroup',
      'col',
    ],
    ADD_ATTR: [
      'class',
      'src',
      'alt',
      'title',
      'loading',
      'decoding',
      'data-eclipso',
      'data-eclipso-name',
      'data-eclipso-page',
      'data-eclipso-tags',
      'data-eclipso-anns',
      'data-id',
      'data-source',
      'data-kind',
      'data-label',
      'data-valid',
      'data-tag',
      'colspan',
      'rowspan',
    ],
    ALLOWED_URI_REGEXP:
      /^(?:(?:https?|mailto|tel):|data:image\/(?:png|jpeg|jpg|gif|webp);base64,)/i,
  })

  viewer.innerHTML = clean
  applyMarkdownTailwind(viewer)
  stripEmailLinks(viewer)
  decorateImagesWithOcrOverlays(viewer)
}

function decorateImagesWithDetectionTags(viewer, detsForViewer) {
  if (!viewer) return

  const imgs = Array.from(viewer.querySelectorAll('img'))
  if (!imgs.length) return

  const parseTagsAttr = (s) => {
    // "OCR·주민등록번호:2|OCR·전화번호:1" -> [ [tag, count], ... ]
    const raw = String(s || '').trim()
    if (!raw) return []
    const parts = raw
      .split('|')
      .map((x) => x.trim())
      .filter(Boolean)
    const out = []
    for (const p of parts) {
      const i = p.lastIndexOf(':')
      if (i <= 0) {
        out.push([p, 1])
        continue
      }
      const tag = p.slice(0, i).trim()
      const n = Number(p.slice(i + 1).trim())
      out.push([tag, Number.isFinite(n) && n > 0 ? n : 1])
    }
    return out
  }

  const chipsFromEntries = (entries) => {
    const maxChips = 10
    const chips = entries.slice(0, maxChips).map(([tag, n]) => {
      const label = n > 1 ? `${tag} · ${n}` : tag
      return `<span class="inline-flex items-center px-2 py-1 rounded-full text-[11px] font-semibold border border-gray-200 bg-white/90 text-gray-800 whitespace-nowrap">${escHtml(
        label
      )}</span>`
    })
    const rest = entries.length - maxChips
    if (rest > 0) {
      chips.push(
        `<span class="inline-flex items-center px-2 py-1 rounded-full text-[11px] font-semibold border border-gray-200 bg-white/90 text-gray-600 whitespace-nowrap">+${rest}</span>`
      )
    }
    return `<div class="absolute top-2 left-2 right-2 flex flex-wrap gap-1 justify-start pointer-events-none">${chips.join(
      ''
    )}</div>`
  }

  // global fallback(이미지별 OCR 태그가 없을 때만)
  const globalCounts = new Map()
  for (const d of Array.isArray(detsForViewer) ? detsForViewer : []) {
    if (!d) continue
    if (d.source === 'regex' && d.valid === false) continue
    const tag =
      d.source === 'regex'
        ? `REGEX·${d.kind || 'UNK'}`
        : `NER·${String(d.label || 'UNK').toUpperCase()}`
    globalCounts.set(tag, (globalCounts.get(tag) || 0) + 1)
  }
  const globalEntries = Array.from(globalCounts.entries()).sort(
    (a, b) => (b[1] || 0) - (a[1] || 0)
  )

  for (const img of imgs) {
    // 이미 래핑된 경우 스킵
    const parent = img.parentElement
    if (!parent) continue
    if (parent.classList.contains('eclipso-img-wrap')) continue

    // img를 감싸고 상단 오버레이를 추가
    const wrap = document.createElement('div')
    wrap.className = 'eclipso-img-wrap relative'
    parent.insertBefore(wrap, img)
    wrap.appendChild(img)

    const ov = document.createElement('div')
    const perImg = parseTagsAttr(img.getAttribute('data-eclipso-tags') || '')
    const entries = perImg.length ? perImg : globalEntries
    if (!entries.length) continue
    ov.innerHTML = chipsFromEntries(entries)
    wrap.appendChild(ov.firstChild)
  }
}

function decorateImagesWithOcrOverlays(viewer) {
  if (!viewer) return

  const imgs = Array.from(viewer.querySelectorAll('img'))
  if (!imgs.length) return

  const b64ToUtf8 = (b64) => {
    const s = String(b64 || '').trim()
    if (!s) return ''
    try {
      const bin = atob(s)
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
      return new TextDecoder('utf-8').decode(bytes)
    } catch {
      return ''
    }
  }

  const parseAnns = (b64) => {
    const raw = b64ToUtf8(b64)
    if (!raw) return []
    try {
      const arr = JSON.parse(raw)
      return Array.isArray(arr) ? arr : []
    } catch {
      return []
    }
  }

  const clamp01 = (x) => Math.max(0, Math.min(1, Number(x)))

  for (const img of imgs) {
    const annsB64 = img.getAttribute('data-eclipso-anns') || ''
    const anns = parseAnns(annsB64)
    if (!anns.length) continue

    const parent = img.parentElement
    if (!parent) continue

    // wrapper가 없으면 생성(칩 함수가 먼저 돌지만, 안전망)
    let wrap = parent.classList.contains('eclipso-img-wrap') ? parent : null
    if (!wrap) {
      wrap = document.createElement('div')
      wrap.className = 'eclipso-img-wrap relative'
      parent.insertBefore(wrap, img)
      wrap.appendChild(img)
    }

    // 기존 레이어 제거(리렌더 시 중복 방지)
    wrap.querySelectorAll('.eclipso-ocr-layer').forEach((el) => el.remove())

    const layer = document.createElement('div')
    layer.className = 'eclipso-ocr-layer absolute inset-0 pointer-events-none'
    wrap.appendChild(layer)

    for (const a of anns) {
      if (!a) continue
      const x0 = clamp01(a.x0)
      const y0 = clamp01(a.y0)
      const x1 = clamp01(a.x1)
      const y1 = clamp01(a.y1)
      if (!(x1 > x0 && y1 > y0)) continue

      const box = document.createElement('div')
      box.className = 'absolute'
      box.style.left = `${(x0 * 100).toFixed(2)}%`
      box.style.top = `${(y0 * 100).toFixed(2)}%`
      box.style.width = `${((x1 - x0) * 100).toFixed(2)}%`
      box.style.height = `${((y1 - y0) * 100).toFixed(2)}%`
      box.style.border = '2px solid rgba(124,58,237,0.95)'
      box.style.background = 'rgba(124,58,237,0.12)'
      box.style.borderRadius = '6px'

      const tag = String(a.tag || '').trim()
      if (tag) {
        const chip = document.createElement('div')
        chip.className =
          'absolute -top-3 left-0 inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold'
        chip.style.background = 'rgba(124,58,237,0.95)'
        chip.style.color = '#fff'
        chip.style.border = '1px solid rgba(124,58,237,1)'
        chip.textContent = tag
        box.appendChild(chip)
      }

      const txt = String(a.text || '').trim()
      if (txt) box.setAttribute('title', txt)

      layer.appendChild(box)
    }
  }
}

function stripEmailLinks(viewer) {
  if (!viewer) return

  const emailRe = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i

  const unwrap = (a) => {
    const p = a.parentNode
    if (!p) return
    while (a.firstChild) p.insertBefore(a.firstChild, a)
    p.removeChild(a)
  }

  viewer.querySelectorAll('a[href]').forEach((a) => {
    const href = String(a.getAttribute('href') || '').trim()
    const hrefLow = href.toLowerCase()
    const text = String(a.textContent || '').trim()

    const looksEmail = emailRe.test(text)
    const isMailto =
      hrefLow.startsWith('mailto:') || hrefLow.includes('mailto:')

    // "이메일 텍스트"를 클릭 링크로 만들지 않기
    if (isMailto && looksEmail) return unwrap(a)

    // 일부 환경에서 href가 이메일 그대로/또는 https://email 형태로 붙는 경우까지 방어
    if (
      looksEmail &&
      (hrefLow === text.toLowerCase() ||
        hrefLow.replace(/^https?:\/\//, '') === text.toLowerCase())
    ) {
      return unwrap(a)
    }
  })
}

function applyMarkdownTailwind(viewer) {
  if (!viewer) return

  const add = (sel, classes) => {
    const cls = String(classes).split(/\s+/).filter(Boolean)
    viewer.querySelectorAll(sel).forEach((el) => el.classList.add(...cls))
  }

  add('h1', 'text-2xl font-semibold mt-6 mb-3 tracking-tight')
  add('h2', 'text-xl font-semibold mt-5 mb-2 tracking-tight')
  add('h3', 'text-lg font-semibold mt-4 mb-2')
  add('p', 'my-2')
  add('ul', 'my-2 pl-5 list-disc')
  add('ol', 'my-2 pl-5 list-decimal')
  add('li', 'my-1')
  add('blockquote', 'my-3 pl-4 border-l-4 border-gray-200 text-gray-600')
  add('a', 'text-blue-600 underline break-words')
  add('hr', 'my-4 border-gray-200')

  add(
    'pre',
    'my-3 bg-[#0b1220] text-gray-200 p-3 rounded-xl overflow-visible whitespace-pre-wrap break-words border border-white/10'
  )
  add('code', 'font-mono text-[12px]')

  add('table', 'w-full border-collapse my-2 text-[12px]')
  add('th', 'border border-gray-200 px-2 py-1 text-left bg-gray-50 align-top')
  add('td', 'border border-gray-200 px-2 py-1 align-top')
  add(
    'img',
    'max-w-full h-auto rounded-lg border border-gray-200 bg-white my-2'
  )
}

function normalizeTsvTablesToMarkdown(md) {
  const src = String(md || '')
  if (!src) return src
  if (src.includes('<table')) return src

  const lines = src.split('\n')
  const out = []
  let inFence = false

  const escCell = (s) => String(s ?? '').replace(/\|/g, '\\|')
  const toPipeRow = (cells) => `| ${cells.map(escCell).join(' | ')} |`

  const isPlaceholderHeader = (v) => {
    const s = String(v || '').trim()
    if (!s) return false
    return /^col\s*\d+$/i.test(s) || /^column\s*\d+$/i.test(s)
  }

  const emitTable = (rows) => {
    if (!rows || rows.length < 2) return false
    const hasSeparator = rows.some(
      (row) => row.length >= 2 && row.every((cell) => /^[ \-\:]+$/.test(cell))
    )
    if (hasSeparator) return false

    const colCount = Math.max(...rows.map((r) => r.length))
    if (colCount < 2) return false
    const norm = rows.map((r) => {
      const rr = r.slice(0, colCount)
      while (rr.length < colCount) rr.push('')
      return rr
    })
    const header = norm[0].map((c) => (isPlaceholderHeader(c) ? '' : c))
    const body = norm.slice(1)
    const sep = Array.from({ length: colCount }, () => '---')
    out.push('', toPipeRow(header), toPipeRow(sep))
    for (const r of body) out.push(toPipeRow(r))
    out.push('')
    return true
  }

  const splitBySpaces = (line) =>
    line
      .trimEnd()
      .split(/\s{2,}/)
      .map((c) => c.trim())
  const splitByPipe = (line) => {
    const s = String(line || '').trim()
    const core = s.replace(/^\|/, '').replace(/\|$/, '')
    return core.split('|').map((c) => c.trim())
  }

  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    const fence = line.trim().startsWith('```')
    if (fence) {
      inFence = !inFence
      out.push(line)
      i++
      continue
    }
    if (inFence) {
      out.push(line)
      i++
      continue
    }

    if (line.includes('\t')) {
      const run = []
      while (
        i < lines.length &&
        lines[i].includes('\t') &&
        lines[i].trim() !== ''
      ) {
        run.push(lines[i])
        i++
      }
      if (run.length >= 2) {
        if (emitTable(run.map((l) => l.split('\t').map((c) => c.trim()))))
          continue
      }
      out.push(...run)
      continue
    }

    if (
      line.includes('|') &&
      line.trim() !== '' &&
      splitByPipe(line).length >= 2
    ) {
      const run = []
      while (
        i < lines.length &&
        lines[i].trim() !== '' &&
        lines[i].includes('|') &&
        splitByPipe(lines[i]).length >= 2
      ) {
        run.push(lines[i])
        i++
      }
      if (run.length >= 2) {
        if (emitTable(run.map(splitByPipe))) continue
      }
      out.push(...run)
      continue
    }

    const looksSpaceTableRow =
      /\s{2,}/.test(line) &&
      splitBySpaces(line).length >= 2 &&
      line.trim() !== ''
    if (looksSpaceTableRow) {
      const run = []
      while (
        i < lines.length &&
        lines[i].trim() !== '' &&
        /\s{2,}/.test(lines[i]) &&
        splitBySpaces(lines[i]).length >= 2
      ) {
        run.push(lines[i])
        i++
      }
      if (run.length >= 3) {
        if (emitTable(run.map(splitBySpaces))) continue
      }
      out.push(...run)
      continue
    }

    out.push(line)
    i++
  }
  return out.join('\n')
}

function applyDocOrientationHint(md, viewerEl = null) {
  const pageEl = document.getElementById('doc-page')
  if (!pageEl) return
  let orient = 'portrait'
  const src = String(md || '')
  if (src.includes('<table')) orient = 'landscape'
  else {
    for (const line of src.split('\n')) {
      if (line.includes('|')) {
        const cols = line.split('|').filter(Boolean).length
        if (cols >= 4) {
          orient = 'landscape'
          break
        }
      }
    }
  }
  const v = viewerEl || document.getElementById('doc-viewer')
  if (v && v.querySelectorAll('table').length > 0) orient = 'landscape'
  pageEl.classList.toggle('max-w-[1018px]', orient === 'landscape')
  pageEl.classList.toggle('max-w-[680px]', orient !== 'landscape')
}

/** ---------- Match / NER Results (right panel) ---------- */
function setActiveResultItem(id) {
  $$('.hit-btn').forEach((el) => {
    el.classList.remove('border-gray-900', 'ring-2', 'ring-gray-900/20')
  })
  $$('.ner-row').forEach((el) => {
    el.classList.remove('bg-indigo-50')
  })
  if (!id) return
  const btn = $(`.hit-btn[data-id="${CSS.escape(id)}"]`)
  if (btn) {
    btn.classList.add('border-gray-900', 'ring-2', 'ring-gray-900/20')
    btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }
  const row = $(`.ner-row[data-id="${CSS.escape(id)}"]`)
  if (row) {
    row.classList.add('bg-indigo-50')
    row.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }
}

function updateSegButtons(seg) {
  const all = document.getElementById('seg-all')
  const ok = document.getElementById('seg-ok')
  const fail = document.getElementById('seg-fail')
  if (!all || !ok || !fail) return

  all.className =
    'px-3 py-1.5 text-xs ' +
    (seg === 'all'
      ? 'bg-gray-900 text-white'
      : 'text-gray-700 hover:bg-gray-50')
  ok.className =
    'px-3 py-1.5 text-xs ' +
    (seg === 'ok'
      ? 'bg-gray-900 text-white'
      : 'text-emerald-700 hover:bg-emerald-50')
  fail.className =
    'px-3 py-1.5 text-xs ' +
    (seg === 'fail'
      ? 'bg-gray-900 text-white'
      : 'text-rose-700 hover:bg-rose-50')
}

function renderMatchResults() {
  const groups = $('#match-groups')
  if (!groups) return

  const seg = state.filters.seg || 'all'
  const q = String(state.filters.q || '')
    .trim()
    .toLowerCase()

  let items = state.detections.filter((d) => d.source === 'regex')
  if (seg === 'ok') items = items.filter((d) => d.valid)
  if (seg === 'fail') items = items.filter((d) => !d.valid)
  if (q) {
    items = items.filter((d) =>
      `${d.text} ${d.kind || ''} ${d.rule || ''}`.toLowerCase().includes(q)
    )
  }

  const total = state.detections.filter((d) => d.source === 'regex').length
  const ok = state.detections.filter(
    (d) => d.source === 'regex' && d.valid
  ).length
  const fail = total - ok

  const summary = $('#summary')
  if (summary) summary.textContent = `총 ${total} · OK ${ok} · FAIL ${fail}`

  groups.innerHTML = ''
  if (!items.length) {
    groups.innerHTML =
      '<div class="text-[12px] text-gray-400 p-3 text-center">표시할 항목이 없습니다.</div>'
    return
  }

  const byKind = new Map()
  for (const d of items) {
    const k = d.kind || 'UNKNOWN'
    if (!byKind.has(k)) byKind.set(k, [])
    byKind.get(k).push(d)
  }

  for (const [k, arr] of byKind.entries()) {
    const card = document.createElement('div')
    card.className = 'rounded-xl border border-gray-200 overflow-hidden'
    card.innerHTML = `<div class="px-3 py-2 text-xs font-semibold bg-gray-50">${escHtml(
      k
    )} <span class="ml-1 text-gray-400 font-normal">${arr.length}</span></div>`

    const body = document.createElement('div')
    body.className = 'p-2 space-y-2'
    for (const d of arr) {
      const btn = document.createElement('button')
      btn.type = 'button'
      btn.className =
        'hit-btn w-full text-left border border-gray-200 rounded-xl px-3 py-2 bg-white hover:bg-gray-50 transition'
      btn.dataset.id = d.id

      const badge = d.valid
        ? '<span class="text-[10px] font-semibold text-emerald-700">OK</span>'
        : '<span class="text-[10px] font-semibold text-rose-700">FAIL</span>'
      btn.innerHTML = `
        <div class="flex items-start justify-between gap-2">
          <div class="min-w-0">
            <div class="text-[10px] opacity-50">${escHtml(d.rule || '')}</div>
            <div class="truncate text-sm">${escHtml(d.text)}</div>
          </div>
          <div class="shrink-0">${badge}</div>
        </div>
      `
      btn.addEventListener('click', () => {
        state.selectedId = d.id
        setActiveResultItem(d.id)
        navigateToAndSelectDetection(d.id)
      })
      body.appendChild(btn)
    }
    card.appendChild(body)
    groups.appendChild(card)
  }
}

function renderNerResults() {
  const rows = $('#ner-rows')
  if (!rows) return

  const items = state.detections.filter((d) => d.source === 'ner')

  const scores = items
    .map((d) => (typeof d.score === 'number' ? d.score : null))
    .filter((x) => x != null)
  const avg = scores.length
    ? scores.reduce((a, b) => a + b, 0) / scores.length
    : null
  const sum = $('#ner-summary')
  if (sum) sum.textContent = `총 ${items.length} · 평균 score ${Score(avg)}`

  rows.innerHTML = ''
  for (const d of items) {
    const tr = document.createElement('tr')
    tr.className = 'ner-row border-b hover:bg-gray-50 cursor-pointer'
    tr.dataset.id = d.id
    tr.innerHTML = `
      <td class="py-2 px-2 font-semibold">${escHtml(d.label || '')}</td>
      <td class="py-2 px-2">${escHtml(d.text)}</td>
      <td class="py-2 px-2 font-mono">${escHtml(Score(d.score))}</td>
      <td class="py-2 px-2 font-mono text-[12px] opacity-70">${escHtml(
        `${d.start ?? '-'}-${d.end ?? '-'}`
      )}</td>
    `
    tr.addEventListener('click', () => {
      state.selectedId = d.id
      setActiveResultItem(d.id)
      navigateToAndSelectDetection(d.id)
    })
    rows.appendChild(tr)
  }
}

function setMatchTab(tab) {
  const t = tab === 'ner' ? 'ner' : 'regex'
  state.ui = state.ui || {}
  state.ui.matchTab = t

  const paneRegex = $('#match-pane-regex')
  const paneNer = $('#match-pane-ner')
  paneRegex && paneRegex.classList.toggle('hidden', t !== 'regex')
  paneNer && paneNer.classList.toggle('hidden', t !== 'ner')

  const label = $('#match-tab-label')
  if (label) label.textContent = t === 'regex' ? '정규식' : 'NER'

  const badge = $('#match-badge')
  if (badge) {
    const n =
      t === 'regex'
        ? state.detections.filter((d) => d.source === 'regex').length
        : state.detections.filter((d) => d.source === 'ner').length
    badge.textContent = String(n)
  }
}

function wireMatchTabs() {
  const prev = $('#btn-match-prev')
  const next = $('#btn-match-next')
  if (prev)
    prev.addEventListener('click', () =>
      setMatchTab((state.ui?.matchTab || 'regex') === 'regex' ? 'ner' : 'regex')
    )
  if (next)
    next.addEventListener('click', () =>
      setMatchTab((state.ui?.matchTab || 'regex') === 'regex' ? 'ner' : 'regex')
    )
}

function wireViewerClick() {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  viewer.addEventListener('click', (e) => {
    const sp = e.target.closest('.pii-box')
    if (!sp) return
    const id = sp.getAttribute('data-id')
    if (!id) return
    state.selectedId = id
    clearViewerSelection()
    applyViewerSelection(id)
    setActiveResultItem(id)
    const d = state.detectionById?.get(id)
    if (d?.source === 'ner') setMatchTab('ner')
    else setMatchTab('regex')
  })
}

/** ---------- Stats & Report ---------- */
function pad2(n) {
  return String(n).padStart(2, '0')
}
function formatIsoToLocalKorean(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(
    d.getDate()
  )} (${pad2(d.getHours())}:${pad2(d.getMinutes())})`
}
function Score(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return '-'
  return v.toFixed(2)
}

function computeScanStats({ matchData, nerItems, nerLabels, timings }) {
  const mdItems = Array.isArray(matchData?.items) ? matchData.items : []
  const ner = Array.isArray(nerItems) ? nerItems : []
  const allow = new Set((nerLabels || []).map((x) => String(x).toUpperCase()))

  let regex_ok = 0,
    regex_fail = 0
  const by_kind = {}
  // FAIL 원인 집계: { "규칙명: 원인": count }
  const fail_reasons = {}

  // 민감정보 span 수집 (노출 비율 계산용)
  const sensitiveSpans = []

  for (const it of mdItems) {
    const isOk = it?.valid !== false
    if (isOk) {
      regex_ok++
      const k = ruleToKind(it.rule)
      by_kind[k] = (by_kind[k] || 0) + 1
      // 유효한 span 수집
      const s = Number(it?.start ?? -1)
      const e = Number(it?.end ?? -1)
      if (e > s && s >= 0) {
        sensitiveSpans.push({ start: s, end: e })
      }
    } else {
      regex_fail++
      // FAIL 원인 집계
      const rule = ruleToKind(it?.rule) || it?.rule || 'UNKNOWN'
      const reason = it?.fail_reason || '검증 실패'
      const key = `${rule}: ${reason}`
      fail_reasons[key] = (fail_reasons[key] || 0) + 1
    }
  }

  const by_label = {}
  const scores = []
  let nerAllowedCount = 0
  let nerAllowedSpanCount = 0
  for (const it of ner) {
    const lab = String(it?.label || '').toUpperCase()
    if (!allow.has(lab)) continue
    nerAllowedCount++
    by_label[lab] = (by_label[lab] || 0) + 1
    if (typeof it?.score === 'number') scores.push(it.score)
    // NER span도 수집
    const s = Number(it?.start ?? -1)
    const e = Number(it?.end ?? -1)
    if (e > s && s >= 0) {
      nerAllowedSpanCount++
      sensitiveSpans.push({ start: s, end: e })
    }
  }

  // ─────────────────────────────────────────────────────
  // 전체 문서 대비 민감정보 노출 비율 계산
  // ─────────────────────────────────────────────────────
  const docText = state.extractedText || ''
  const totalChars = docText.length

  // span 병합 (겹치는 영역 제거)
  const mergedSpans = mergeOverlappingSpans(sensitiveSpans)

  // 민감정보가 차지하는 총 글자 수
  let sensitiveChars = 0
  for (const sp of mergedSpans) {
    sensitiveChars += Math.min(sp.end, totalChars) - Math.max(sp.start, 0)
  }

  // 노출 비율 (%)
  const exposureRatio = totalChars > 0 ? (sensitiveChars / totalChars) * 100 : 0

  const nerAvg = scores.length
    ? scores.reduce((a, b) => a + b, 0) / scores.length
    : null

  // Unique(실제 표시/레닥션 가능한 span 기준): valid!=false + start/end 유효
  const dets = Array.isArray(state.detections) ? state.detections : []
  const detsSpan = dets.filter((d) => {
    if (!d) return false
    if (d.valid === false) return false
    const s = Number(d.start ?? -1)
    const e = Number(d.end ?? -1)
    return e > s && s >= 0
  })
  const regexUnique = detsSpan.filter((d) => d.source === 'regex').length
  const nerUnique = detsSpan.filter((d) => d.source === 'ner').length
  const totalUnique = detsSpan.length

  // Raw(중복 제거 전): 정규식 OK span + 허용된 NER span
  const regexRawSpan = mdItems.filter((it) => {
    if (it?.valid === false) return false
    const s = Number(it?.start ?? -1)
    const e = Number(it?.end ?? -1)
    return e > s && s >= 0
  }).length
  const totalRaw = regexRawSpan + nerAllowedSpanCount

  const overlapRate =
    totalRaw > 0 ? Math.max(0, Math.min(100, ((totalRaw - totalUnique) / totalRaw) * 100)) : 0

  return {
    exposure_ratio: exposureRatio,
    total_chars: totalChars,
    sensitive_chars: sensitiveChars,
    total_raw: totalRaw,
    total_unique: totalUnique,
    regex_unique: regexUnique,
    ner_unique: nerUnique,
    overlap_rate: overlapRate,
    regex_ok,
    regex_fail,
    fail_reasons,
    by_kind,
    by_label,
    ner_avg: Score(nerAvg),
    timings: timings || {},
  }
}

// 겹치는 span 병합
function mergeOverlappingSpans(spans) {
  if (!spans || spans.length === 0) return []

  // 시작점 기준 정렬
  const sorted = [...spans].sort((a, b) => a.start - b.start)
  const merged = [sorted[0]]

  for (let i = 1; i < sorted.length; i++) {
    const last = merged[merged.length - 1]
    const curr = sorted[i]

    if (curr.start <= last.end) {
      // 겹치거나 붙어있으면 병합
      last.end = Math.max(last.end, curr.end)
    } else {
      merged.push({ start: curr.start, end: curr.end })
    }
  }

  return merged
}

function renderScanReport(stats) {
  if (!stats) return

  // stats 블록은 있어도 되고 없어도 됨(없으면 그냥 스킵)
  safeShow('stats-report-block', true)

  // 민감정보 비율 표시
  const ratio = stats.exposure_ratio || 0
  safeText('stats-exposure-ratio', ratio.toFixed(2))

  // 미터 (최대 10%를 100%로 스케일링)
  const meterPct = Math.min(100, ratio * 10)
  safeWidthPct('stats-exposure-meter', `${meterPct}%`)

  // 노트 표시
  const noteEl = byId('stats-exposure-note')
  if (noteEl) {
    const totalChars = stats.total_chars || 0
    const sensitiveChars = stats.sensitive_chars || 0
    if (totalChars > 0) {
      noteEl.textContent = `${sensitiveChars.toLocaleString()}자 / ${totalChars.toLocaleString()}자`
    } else {
      noteEl.textContent = '전체 문서 대비 민감정보 글자 수'
    }
  }

  safeText('stats-total-unique', stats.total_unique)
  safeText('stats-total-raw', stats.total_raw)
  safeText('stats-regex-unique', stats.regex_unique)
  safeText('stats-ner-unique', stats.ner_unique)
  safeText('stats-overlap-rate', `${Math.round(stats.overlap_rate || 0)}%`)
  safeText('stats-regex-ok', stats.regex_ok)
  safeText('stats-regex-fail', stats.regex_fail)
  safeText('stats-ner-avg', stats.ner_avg)

  // FAIL 원인 표시
  const failTopEl = byId('stats-fail-top')
  if (failTopEl) {
    const reasons = stats.fail_reasons || {}
    const entries = Object.entries(reasons).sort((a, b) => b[1] - a[1])

    if (entries.length === 0) {
      failTopEl.innerHTML = '<span class="text-gray-400">-</span>'
    } else {
      failTopEl.innerHTML = entries
        .map(
          ([reason, count]) =>
            `<div class="flex justify-between items-center py-1 border-b border-gray-100 last:border-0">
              <span class="text-rose-600 text-[11px]">${escHtml(reason)}</span>
              <span class="text-gray-500 font-mono text-[11px] ml-2">${count}</span>
            </div>`
        )
        .join('')
    }
  }

  const kindBody = byId('stats-by-kind-rows')
  if (kindBody) {
    kindBody.innerHTML = Object.entries(stats.by_kind || {})
      .sort((a, b) => b[1] - a[1])
      .map(
        ([k, v]) =>
          `<tr>
            <td class="py-2 pl-4 pr-2 font-medium text-zinc-900">${escHtml(
              k
            )}</td>
            <td class="py-2 pr-5 text-right font-bold text-zinc-500">${escHtml(
              v
            )}</td>
          </tr>`
      )
      .join('')
  }

  const labelBody = byId('stats-by-label-rows')
  if (labelBody) {
    labelBody.innerHTML = Object.entries(stats.by_label || {})
      .sort((a, b) => b[1] - a[1])
      .map(
        ([k, v]) =>
          `<tr>
            <td class="py-2 pl-4 pr-2 font-medium text-zinc-900">${escHtml(
              k
            )}</td>
            <td class="py-2 pr-5 text-right font-bold text-zinc-500">${escHtml(
              v
            )}</td>
          </tr>`
      )
      .join('')
  }

  safeText('t-extract', Math.round(stats.timings.extract_ms || 0) + 'ms')
  safeText('t-match', Math.round(stats.timings.match_ms || 0) + 'ms')
  safeText('t-ner', Math.round(stats.timings.ner_ms || 0) + 'ms')
  safeText('t-redact', Math.round(stats.timings.redact_ms || 0) + 'ms')
  safeText('t-total', Math.round(stats.timings.total_ms || 0) + 'ms')

  // 정책(선택한 규칙/라벨 표시)
  const selectedRules = Array.isArray(state.rules) ? state.rules : []
  const selectedNer = Array.isArray(state.nerLabels) ? state.nerLabels : []

  const detectedRuleSet = new Set()
  const mdItems = Array.isArray(state.matchData?.items)
    ? state.matchData.items
    : []
  for (const it of mdItems) {
    if (it?.valid === false) continue
    if (!it?.rule) continue
    detectedRuleSet.add(String(it.rule))
  }

  const rulesBox = byId('stats-policy-rules')
  if (rulesBox) {
    rulesBox.innerHTML = selectedRules
      .map((r) => {
        const isHit = detectedRuleSet.has(String(r))
        const label = ruleToKind(r)
        const cls = isHit
          ? 'border-indigo-200 bg-indigo-50 text-indigo-700'
          : 'border-gray-200 bg-gray-50 text-gray-600'
        return `<span class="inline-flex items-center gap-1 px-2 py-1 rounded-full border text-[11px] ${cls}">${escHtml(
          label
        )}</span>`
      })
      .join('')
  }

  const nerBox = byId('stats-policy-nerlabels')
  if (nerBox) {
    // "감지된 NER 라벨" 기준으로 표시(정책은 선택 라벨, 강조는 감지 여부)
    const detectedLabelSet = new Set(
      Object.keys(stats.by_label || {}).map((x) => String(x).toUpperCase())
    )

    const chips = (selectedNer || []).map((labRaw) => {
      const lab = String(labRaw).toUpperCase()
      const hit = detectedLabelSet.has(lab)
      const cnt = hit ? Number(stats.by_label?.[lab] || 0) : 0
      const cls = hit
        ? 'border-indigo-200 bg-indigo-50 text-indigo-700'
        : 'border-gray-200 bg-gray-50 text-gray-600'
      const suffix = hit && cnt ? ` · ${cnt}` : ''
      return `<span class="inline-flex items-center px-2 py-1 rounded-full border text-[11px] ${cls}">${escHtml(
        lab + suffix
      )}</span>`
    })

    if (!chips.length) {
      nerBox.innerHTML =
        '<span class="inline-flex items-center px-2 py-1 rounded-full border border-gray-200 bg-gray-50 text-gray-600 text-[11px]">없음</span>'
    } else {
      nerBox.innerHTML = chips.join('')
    }
  }

  // JSON 패널 제거됨
}

/** ---------- Main: Scan ---------- */
async function doScan() {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  state.file = f
  state.ext = (f.name.split('.').pop() || '').toLowerCase()
  state.rules = selectedRuleNames()
  state.nerLabels = selectedNerLabels()
  state.t0 = performance.now()

  setStatus('분석 준비 중...')
  setStatusSub('')
  setProgress(0, '대기', { forceShow: false })
  lockInputs(true)

  try {
    const fd = new FormData()
    fd.append('file', f)

    const t1 = performance.now()
    setStatus('텍스트 추출 중...')
    setStatusSub('파일 업로드 · 서버 처리')
    setProgress(10, '텍스트 추출', { forceShow: true })
    const r1 = await fetch(`${API_BASE()}/text/extract`, {
      method: 'POST',
      body: fd,
    })
    if (!r1.ok) throw new Error('추출 실패')
    const extractData = await r1.json()
    state.timings = { extract_ms: performance.now() - t1 }

    const fullText = String(extractData.full_text || '')
    state.extractedText = fullText
    setStatusSub(`추출 완료 · ${fullText.length.toLocaleString()} chars`)
    setProgress(35, '텍스트 추출 완료', { forceShow: true })

    const md = extractData.markdown || fallbackMarkdownFromText(fullText)
    const pages = buildPagesFromExtractData(extractData, md)
    setPages(pages)
    state.markdown = String(state.pages[state.pageIndex] || '')

    const t2 = performance.now()
    setStatus('패턴 탐색 중...')
    setStatusSub('정규식 규칙 매칭')
    setProgress(45, '패턴 탐색', { forceShow: true })
    const r2 = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: fullText,
        rules: state.rules,
        normalize: true,
      }),
    })
    const rawMatchData = await r2.json()
    state.timings.match_ms = performance.now() - t2
    state.matchData = filterMatchByRules(rawMatchData, state.rules)

    const matchItems = Array.isArray(state.matchData?.items)
      ? state.matchData.items
      : []
    const matchValid = matchItems.filter((x) => x?.valid !== false).length
    setStatusSub(`패턴 탐색 완료 · ${matchValid.toLocaleString()}건`)
    setProgress(60, '패턴 탐색 완료', { forceShow: true })

    const t3 = performance.now()
    setStatus('NER 탐지 중...')
    setStatusSub(
      `라벨: ${
        (state.nerLabels || [])
          .map((x) => String(x).toUpperCase())
          .join(', ') || '-'
      } · 서버 처리`
    )
    setProgress(70, 'NER 탐지', { forceShow: true })
    const nerResp = await requestNerSmart(
      fullText,
      buildExcludeSpansFromMatch(state.matchData),
      state.nerLabels
    )
    state.timings.ner_ms = performance.now() - t3
    state.nerItems = nerResp.items
    setStatusSub(`NER 탐지 완료 · ${state.nerItems.length.toLocaleString()}건`)
    setProgress(85, 'NER 탐지 완료', { forceShow: true })

    state.detections = buildDetections(
      state.matchData,
      state.nerItems,
      state.nerLabels,
      state.extractedText
    )
    state.detectionById = new Map(state.detections.map((d) => [d.id, d]))

    safeClassRemove('doc-viewer-block', 'hidden')
    safeClassRemove('match-tabs-block', 'hidden')
    safeText(
      'doc-meta',
      `${f.name} · ${state.ext.toUpperCase()} · ${Math.round(f.size / 1024)}KB`
    )
    safeText('doc-detect-count', state.detections.length)

    // 오른쪽 badge(현재 탭은 setMatchTab에서 갱신)
    const mb = byId('match-badge')
    if (mb) {
      mb.textContent = String(
        state.detections.filter((d) => d.source === 'regex').length
      )
    }

    setStatus('결과 렌더링 중...')
    setStatusSub('하이라이트/목록 생성')
    setProgress(95, '렌더링', { forceShow: true })

    renderCurrentPage()
    wireViewerClick()
    renderMatchResults()
    renderNerResults()
    setMatchTab('regex')

    state.timings.total_ms = performance.now() - state.t0
    renderScanReport(
      computeScanStats({
        matchData: state.matchData,
        nerItems: state.nerItems,
        nerLabels: state.nerLabels,
        timings: state.timings,
      })
    )

    const totalMs = Math.round(state.timings.total_ms || 0)
    setStatus('완료')
    setStatusSub(totalMs ? `총 소요: ${totalMs.toLocaleString()}ms` : '')
    setProgress(100, '완료', { forceShow: true })

    const btn = $('#btn-save-redacted')
    if (btn) {
      btn.classList.remove('hidden')
      btn.disabled = false
    }
  } catch (e) {
    console.error(e)
    setStatus('오류 발생')
    setStatusSub(e?.message ? String(e.message) : '')
    setProgress(0, '오류', { forceShow: true })
  } finally {
    lockInputs(false)
  }
}

/** ---------- Redact + Download ---------- */
async function doRedactAndDownload() {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  if (!state.file || state.file !== f || !state.extractedText) {
    await doScan()
  }
  if (!state.file) return

  const btn = $('#btn-save-redacted')
  btn && (btn.disabled = true)

  setStatus('레닥션 실행 중...')
  setStatusSub('파일 업로드 · 서버 마스킹')
  setProgress(10, '레닥션', { forceShow: true })
  lockInputs(true)

  const t0 = performance.now()
  try {
    const fd = new FormData()
    fd.append('file', state.file)

    const rulesJson = safeJson(state.rules || [])
    const labelsJson = safeJson(state.nerLabels || [])
    const uiNerEntities = (
      Array.isArray(state.detections) ? state.detections : []
    )
      .filter(
        (d) =>
          d?.source === 'ner' &&
          Number.isFinite(+d?.start) &&
          Number.isFinite(+d?.end)
      )
      .map((d) => ({
        label: String(d?.label || '').toUpperCase(),
        start: +d.start,
        end: +d.end,
        score: typeof d?.score === 'number' ? d.score : null,
        text: String(d?.text ?? ''),
      }))
    const entsJson = safeJson(uiNerEntities)
    const maskingJson = safeJson(state.maskingPolicy || {})

    rulesJson && fd.append('rules_json', rulesJson)
    labelsJson && fd.append('ner_labels_json', labelsJson)
    entsJson && fd.append('ner_entities_json', entsJson)
    maskingJson &&
      maskingJson !== '{}' &&
      fd.append('masking_json', maskingJson)

    const r = await fetch(`${API_BASE()}/redact/file`, {
      method: 'POST',
      body: fd,
    })
    if (!r.ok) {
      const msg = await r.text().catch(() => '')
      throw new Error(msg || '레닥션 실패')
    }

    const blob = await r.blob()
    setProgress(85, '다운로드 준비', { forceShow: true })
    const cd = r.headers.get('Content-Disposition')
    const filename =
      parseContentDispositionFilename(cd) ||
      buildRedactedFallbackName(state.file?.name)

    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1500)

    state.timings = state.timings || {}
    state.timings.redact_ms = performance.now() - t0
    safeText('t-redact', Math.round(state.timings.redact_ms) + 'ms')

    if (state.t0) {
      state.timings.total_ms = performance.now() - state.t0
      safeText('t-total', Math.round(state.timings.total_ms) + 'ms')
    }

    setStatus('레닥션 완료 · 다운로드 시작')
    setStatusSub('')
    setProgress(100, '레닥션 완료', { forceShow: true })
  } catch (e) {
    console.error(e)
    alert(`레닥션 실패: ${e?.message || e}`)
    setStatus('레닥션 오류')
    setStatusSub(e?.message ? String(e.message) : '')
    setProgress(0, '오류', { forceShow: true })
  } finally {
    btn && (btn.disabled = false)
    lockInputs(false)
  }
}

function renderCurrentPage() {
  // pages 기반 렌더링: 항상 현재 페이지 markdown을 state.markdown에 반영
  state.markdown = String(state.pages?.[state.pageIndex] || '')
  updatePageControls()
  renderMarkdownToViewer(state.markdown, state.detections)
  applyDocOrientationHint(state.markdown, $('#doc-viewer'))
}

/** ---------- Init ---------- */
document.addEventListener('DOMContentLoaded', () => {
  // hydrate NER label checkboxes from prefs (optional)
  try {
    const p = loadPrefs()
    const ner =
      p?.nerLabels && typeof p.nerLabels === 'object' ? p.nerLabels : null
    if (ner) {
      const ps = document.getElementById('ner-show-ps')
      const lc = document.getElementById('ner-show-lc')
      const og = document.getElementById('ner-show-og')
      if (ps && typeof ner.ps === 'boolean') ps.checked = ner.ps
      if (lc && typeof ner.lc === 'boolean') lc.checked = ner.lc
      if (og && typeof ner.og === 'boolean') og.checked = ner.og
    }
  } catch {}

  loadRules()
  setupDropZone()
  wireMatchTabs()
  updateSegButtons(state.filters.seg || 'all')
  resetProgress()
  setupPsMaskModeButton()
  ;['ner-show-ps', 'ner-show-lc', 'ner-show-og'].forEach((id) => {
    const el = document.getElementById(id)
    if (!el) return
    el.addEventListener('change', () => {
      savePrefs({
        nerLabels: {
          ps: document.getElementById('ner-show-ps')?.checked !== false,
          lc: document.getElementById('ner-show-lc')?.checked !== false,
          og: document.getElementById('ner-show-og')?.checked !== false,
        },
      })
    })
  })

  $('#file')?.addEventListener('change', () => {
    const btn = $('#btn-save-redacted')
    if (btn) {
      btn.classList.add('hidden')
      btn.disabled = true
    }
    state.file = $('#file')?.files?.[0] || null
    state.extractedText = ''
    state.markdown = ''
    state.matchData = null
    state.nerItems = []
    state.detections = []
    state.detectionById = new Map()
    state.timings = null
    state.t0 = null
    setStatus('파일 선택됨 · 스캔 실행')
    setStatusSub('')
    setProgress(0, '대기', { forceShow: false })
  })

  $('#filter-search')?.addEventListener('input', (e) => {
    state.filters.q = e.target.value
    renderMatchResults()
  })
  ;['seg-all', 'seg-ok', 'seg-fail'].forEach((id) => {
    const el = document.getElementById(id)
    if (!el) return
    el.addEventListener('click', () => {
      state.filters.seg = el.dataset.seg || 'all'
      updateSegButtons(state.filters.seg)
      renderMatchResults()
    })
  })

  $('#btn-scan')?.addEventListener('click', doScan)
  $('#btn-save-redacted')?.addEventListener('click', doRedactAndDownload)
  // stats JSON 토글 제거됨

  // 문서 페이지 이동
  $('#btn-page-prev')?.addEventListener('click', () => {
    state.pageIndex = Math.max(0, (state.pageIndex || 0) - 1)
    state.selectedId = null
    clearViewerSelection()
    renderCurrentPage()
  })
  $('#btn-page-next')?.addEventListener('click', () => {
    const total = Math.max(1, state.pages.length || 1)
    state.pageIndex = Math.min(total - 1, (state.pageIndex || 0) + 1)
    state.selectedId = null
    clearViewerSelection()
    renderCurrentPage()
  })
})
