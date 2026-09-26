import { BinaryInfo, entropyBlocks, extractStrings, parseBinary } from "./parser.js"

const drop = document.querySelector<HTMLElement>("#drop")!
const input = document.querySelector<HTMLInputElement>("#file")!
const empty = document.querySelector<HTMLElement>("#empty")!
const workspace = document.querySelector<HTMLElement>("#workspace")!
const summary = document.querySelector<HTMLElement>("#summary")!
const sections = document.querySelector<HTMLElement>("#sections")!
const strings = document.querySelector<HTMLElement>("#strings")!
const hex = document.querySelector<HTMLElement>("#hex")!
const map = document.querySelector<HTMLCanvasElement>("#entropy")!
const offsetInput = document.querySelector<HTMLInputElement>("#offset")!
const searchInput = document.querySelector<HTMLInputElement>("#search")!
const filename = document.querySelector<HTMLElement>("#filename")!
const status = document.querySelector<HTMLElement>("#status")!

let bytes = new Uint8Array()
let info: BinaryInfo | null = null
let hexOffset = 0

function formatSize(value: number): string {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / 1024 / 1024).toFixed(2)} MiB`
}

function h(value: number, width = 0): string {
  return `0x${value.toString(16).padStart(width, "0")}`
}

function escapeHtml(value: string): string {
  const node = document.createElement("span")
  node.textContent = value
  return node.innerHTML
}

async function sha256(data: Uint8Array): Promise<string> {
  const copy = new Uint8Array(data).buffer
  const digest = await crypto.subtle.digest("SHA-256", copy)
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("")
}

function renderSummary(file: File, hash: string): void {
  if (!info) return
  const cards: [string, string][] = [
    ["Format", info.format],
    ["Architecture", info.architecture],
    ["Size", formatSize(file.size)],
    ["Entry point", h(info.entryPoint)],
    ["Image base", h(info.imageBase)],
    ["Sections", String(info.sections.length)],
    ["Endian", info.endian],
    ["SHA-256", hash]
  ]
  for (const [key, value] of Object.entries(info.details)) cards.push([key, typeof value === "number" ? h(value) : value])
  summary.innerHTML = cards.map(([key, value]) => `<div class="metric"><span>${escapeHtml(key)}</span><strong title="${escapeHtml(value)}">${escapeHtml(value)}</strong></div>`).join("")
}

function renderSections(): void {
  if (!info) return
  sections.innerHTML = `
    <div class="table-row table-head"><span>Name</span><span>File offset</span><span>Address</span><span>Raw size</span><span>Flags</span><span>Entropy</span></div>
    ${info.sections.map((s, i) => `<button class="table-row" data-section="${i}"><span>${escapeHtml(s.name)}</span><span>${h(s.offset)}</span><span>${h(s.address)}</span><span>${formatSize(s.size)}</span><span class="flags">${s.flags}</span><span>${s.entropy.toFixed(3)}</span></button>`).join("")}
  `
  sections.querySelectorAll<HTMLElement>("[data-section]").forEach(row => {
    row.addEventListener("click", () => {
      const section = info!.sections[Number(row.dataset.section)]
      hexOffset = Math.min(section.offset, Math.max(0, bytes.length - 1))
      offsetInput.value = h(hexOffset)
      renderHex()
    })
  })
}

function entropyColor(value: number): string {
  const ratio = Math.max(0, Math.min(1, value / 8))
  const hue = 190 - ratio * 175
  const light = 28 + ratio * 32
  return `hsl(${hue} 88% ${light}%)`
}

function renderEntropy(): void {
  const values = entropyBlocks(bytes)
  const ratio = window.devicePixelRatio || 1
  const width = map.clientWidth
  const cell = Math.max(3, Math.floor(width / Math.min(values.length, 128)))
  const cols = Math.max(1, Math.floor(width / cell))
  const rows = Math.ceil(values.length / cols)
  map.width = Math.floor(width * ratio)
  map.height = Math.max(72, rows * cell) * ratio
  map.style.height = `${Math.max(72, rows * cell)}px`
  const ctx = map.getContext("2d")!
  ctx.scale(ratio, ratio)
  ctx.fillStyle = "#071018"
  ctx.fillRect(0, 0, width, map.height / ratio)
  values.forEach((value, i) => {
    const x = (i % cols) * cell
    const y = Math.floor(i / cols) * cell
    ctx.fillStyle = entropyColor(value)
    ctx.fillRect(x, y, cell - 1, cell - 1)
  })
  map.onclick = event => {
    const rect = map.getBoundingClientRect()
    const x = event.clientX - rect.left
    const y = event.clientY - rect.top
    const index = Math.floor(y / cell) * cols + Math.floor(x / cell)
    if (index >= values.length) return
    hexOffset = Math.min(index * 512, Math.max(0, bytes.length - 1))
    offsetInput.value = h(hexOffset)
    renderHex()
  }
}

function renderStrings(): void {
  const query = searchInput.value.toLowerCase()
  const found = extractStrings(bytes).filter(item => !query || item.value.toLowerCase().includes(query)).slice(0, 600)
  strings.innerHTML = found.length
    ? found.map(item => `<button class="string-row" data-offset="${item.offset}"><span>${h(item.offset, 8)}</span><code>${escapeHtml(item.value)}</code></button>`).join("")
    : `<div class="muted">No matching strings</div>`
  strings.querySelectorAll<HTMLElement>("[data-offset]").forEach(row => {
    row.addEventListener("click", () => {
      hexOffset = Number(row.dataset.offset)
      offsetInput.value = h(hexOffset)
      renderHex()
    })
  })
}

function renderHex(): void {
  const start = Math.max(0, Math.min(hexOffset, Math.max(0, bytes.length - 1))) & ~0xf
  const end = Math.min(bytes.length, start + 16 * 24)
  const rows: string[] = []
  for (let at = start; at < end; at += 16) {
    const chunk = bytes.slice(at, Math.min(at + 16, end))
    const raw = Array.from(chunk, value => value.toString(16).padStart(2, "0"))
    const left = raw.slice(0, 8).join(" ").padEnd(23, " ")
    const right = raw.slice(8).join(" ").padEnd(23, " ")
    const ascii = Array.from(chunk, value => value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".").join("")
    rows.push(`<div class="hex-row"><span>${h(at, 8)}</span><code>${left}  ${right}</code><em>${escapeHtml(ascii)}</em></div>`)
  }
  hex.innerHTML = rows.join("") || `<div class="muted">Empty file</div>`
}

async function inspect(file: File): Promise<void> {
  status.textContent = "reading"
  const buffer = await file.arrayBuffer()
  bytes = new Uint8Array(buffer)
  filename.textContent = file.name
  info = parseBinary(bytes)
  const hash = await sha256(bytes)
  empty.hidden = true
  workspace.hidden = false
  renderSummary(file, hash)
  renderSections()
  renderEntropy()
  renderStrings()
  hexOffset = 0
  offsetInput.value = "0x0"
  renderHex()
  status.textContent = `${info.format} · ${formatSize(bytes.length)}`
}

function accept(files: FileList | null): void {
  const file = files?.[0]
  if (!file) return
  inspect(file).catch(error => {
    status.textContent = error instanceof Error ? error.message : String(error)
  })
}

drop.addEventListener("click", () => input.click())
drop.addEventListener("dragover", event => {
  event.preventDefault()
  drop.classList.add("active")
})
drop.addEventListener("dragleave", () => drop.classList.remove("active"))
drop.addEventListener("drop", event => {
  event.preventDefault()
  drop.classList.remove("active")
  accept(event.dataTransfer?.files ?? null)
})
input.addEventListener("change", () => accept(input.files))
searchInput.addEventListener("input", renderStrings)
offsetInput.addEventListener("change", () => {
  const value = offsetInput.value.trim().toLowerCase()
  hexOffset = value.startsWith("0x") ? Number.parseInt(value.slice(2), 16) : Number.parseInt(value, 10)
  if (!Number.isFinite(hexOffset)) hexOffset = 0
  renderHex()
})
window.addEventListener("resize", () => {
  if (bytes.length) renderEntropy()
})
