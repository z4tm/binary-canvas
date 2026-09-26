export type BinaryFormat = "PE32" | "PE32+" | "ELF32" | "ELF64" | "Unknown"

export interface BinarySection {
  name: string
  offset: number
  size: number
  address: number
  virtualSize: number
  flags: string
  entropy: number
}

export interface BinaryInfo {
  format: BinaryFormat
  architecture: string
  endian: "little" | "big"
  entryPoint: number
  imageBase: number
  sections: BinarySection[]
  details: Record<string, string | number>
}

const machines: Record<number, string> = {
  0x014c: "x86",
  0x8664: "x86-64",
  0x01c0: "ARM",
  0xaa64: "AArch64",
  3: "x86",
  40: "ARM",
  62: "x86-64",
  183: "AArch64",
  243: "RISC-V"
}

function requireRange(data: Uint8Array, offset: number, size: number): void {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || offset + size > data.length) {
    throw new Error(`invalid range 0x${offset.toString(16)} + ${size}`)
  }
}

function view(data: Uint8Array): DataView {
  return new DataView(data.buffer, data.byteOffset, data.byteLength)
}

function text(data: Uint8Array, offset: number, size: number): string {
  requireRange(data, offset, size)
  let result = ""
  for (let i = 0; i < size && data[offset + i] !== 0; i++) result += String.fromCharCode(data[offset + i])
  return result
}

function u64(v: DataView, offset: number, little: boolean): number {
  const value = v.getBigUint64(offset, little)
  const n = Number(value)
  if (!Number.isSafeInteger(n)) throw new Error("64-bit value exceeds JavaScript safe integer range")
  return n
}

export function entropy(data: Uint8Array, offset = 0, size = data.length - offset): number {
  requireRange(data, offset, size)
  if (size === 0) return 0
  const frequencies = new Uint32Array(256)
  for (let i = offset; i < offset + size; i++) frequencies[data[i]]++
  let value = 0
  for (const count of frequencies) {
    if (count === 0) continue
    const p = count / size
    value -= p * Math.log2(p)
  }
  return value
}

function peFlags(flags: number): string {
  const out: string[] = []
  if (flags & 0x20000000) out.push("X")
  if (flags & 0x40000000) out.push("R")
  if (flags & 0x80000000) out.push("W")
  return out.join("") || "-"
}

function elfFlags(flags: number): string {
  const out: string[] = []
  if (flags & 4) out.push("R")
  if (flags & 2) out.push("W")
  if (flags & 1) out.push("X")
  return out.join("") || "-"
}

export function parsePE(data: Uint8Array): BinaryInfo {
  requireRange(data, 0, 0x40)
  const v = view(data)
  if (v.getUint16(0, true) !== 0x5a4d) throw new Error("missing MZ signature")
  const pe = v.getUint32(0x3c, true)
  requireRange(data, pe, 24)
  if (v.getUint32(pe, true) !== 0x00004550) throw new Error("missing PE signature")

  const machine = v.getUint16(pe + 4, true)
  const sectionCount = v.getUint16(pe + 6, true)
  const timestamp = v.getUint32(pe + 8, true)
  const optionalSize = v.getUint16(pe + 20, true)
  const optional = pe + 24
  requireRange(data, optional, optionalSize)
  const magic = v.getUint16(optional, true)
  if (magic !== 0x10b && magic !== 0x20b) throw new Error("unsupported PE optional header")

  const is64 = magic === 0x20b
  const entryRva = v.getUint32(optional + 16, true)
  const imageBase = is64 ? u64(v, optional + 24, true) : v.getUint32(optional + 28, true)
  const sectionAlignment = v.getUint32(optional + 32, true)
  const fileAlignment = v.getUint32(optional + 36, true)
  const imageSize = v.getUint32(optional + 56, true)
  const subsystem = v.getUint16(optional + 68, true)
  const sectionTable = optional + optionalSize
  requireRange(data, sectionTable, sectionCount * 40)

  const sections: BinarySection[] = []
  for (let i = 0; i < sectionCount; i++) {
    const at = sectionTable + i * 40
    const name = text(data, at, 8) || `<section-${i}>`
    const virtualSize = v.getUint32(at + 8, true)
    const address = v.getUint32(at + 12, true)
    const size = v.getUint32(at + 16, true)
    const offset = v.getUint32(at + 20, true)
    const characteristics = v.getUint32(at + 36, true)
    const available = offset <= data.length ? Math.min(size, data.length - offset) : 0
    sections.push({
      name,
      offset,
      size,
      address,
      virtualSize,
      flags: peFlags(characteristics),
      entropy: available > 0 ? entropy(data, offset, available) : 0
    })
  }

  return {
    format: is64 ? "PE32+" : "PE32",
    architecture: machines[machine] ?? `machine-0x${machine.toString(16)}`,
    endian: "little",
    entryPoint: imageBase + entryRva,
    imageBase,
    sections,
    details: {
      "COFF timestamp": timestamp,
      "Section alignment": sectionAlignment,
      "File alignment": fileAlignment,
      "Image size": imageSize,
      Subsystem: subsystem
    }
  }
}

export function parseELF(data: Uint8Array): BinaryInfo {
  requireRange(data, 0, 0x34)
  if (data[0] !== 0x7f || data[1] !== 0x45 || data[2] !== 0x4c || data[3] !== 0x46) throw new Error("missing ELF signature")
  const cls = data[4]
  const encoding = data[5]
  if (cls !== 1 && cls !== 2) throw new Error("unsupported ELF class")
  if (encoding !== 1 && encoding !== 2) throw new Error("unsupported ELF endianness")

  const little = encoding === 1
  const is64 = cls === 2
  const v = view(data)
  const type = v.getUint16(16, little)
  const machine = v.getUint16(18, little)
  const entryPoint = is64 ? u64(v, 24, little) : v.getUint32(24, little)
  const sectionOffset = is64 ? u64(v, 40, little) : v.getUint32(32, little)
  const flags = v.getUint32(is64 ? 48 : 36, little)
  const sectionEntrySize = v.getUint16(is64 ? 58 : 46, little)
  const sectionCount = v.getUint16(is64 ? 60 : 48, little)
  const stringIndex = v.getUint16(is64 ? 62 : 50, little)
  const minimumEntry = is64 ? 64 : 40
  if (sectionEntrySize < minimumEntry && sectionCount > 0) throw new Error("invalid ELF section entry size")
  requireRange(data, sectionOffset, sectionEntrySize * sectionCount)

  let stringOffset = 0
  let stringSize = 0
  if (stringIndex < sectionCount) {
    const at = sectionOffset + stringIndex * sectionEntrySize
    stringOffset = is64 ? u64(v, at + 24, little) : v.getUint32(at + 16, little)
    stringSize = is64 ? u64(v, at + 32, little) : v.getUint32(at + 20, little)
    requireRange(data, stringOffset, stringSize)
  }

  const sectionName = (index: number): string => {
    if (index >= stringSize) return ""
    let end = stringOffset + index
    const limit = stringOffset + stringSize
    while (end < limit && data[end] !== 0) end++
    return text(data, stringOffset + index, end - stringOffset - index)
  }

  const sections: BinarySection[] = []
  for (let i = 0; i < sectionCount; i++) {
    const at = sectionOffset + i * sectionEntrySize
    const nameIndex = v.getUint32(at, little)
    const sectionFlags = is64 ? u64(v, at + 8, little) : v.getUint32(at + 8, little)
    const address = is64 ? u64(v, at + 16, little) : v.getUint32(at + 12, little)
    const offset = is64 ? u64(v, at + 24, little) : v.getUint32(at + 16, little)
    const size = is64 ? u64(v, at + 32, little) : v.getUint32(at + 20, little)
    const available = offset <= data.length ? Math.min(size, data.length - offset) : 0
    sections.push({
      name: sectionName(nameIndex) || `<section-${i}>`,
      offset,
      size,
      address,
      virtualSize: size,
      flags: elfFlags(sectionFlags),
      entropy: available > 0 ? entropy(data, offset, available) : 0
    })
  }

  return {
    format: is64 ? "ELF64" : "ELF32",
    architecture: machines[machine] ?? `machine-${machine}`,
    endian: little ? "little" : "big",
    entryPoint,
    imageBase: 0,
    sections,
    details: {
      Type: type,
      Flags: `0x${flags.toString(16)}`,
      "Section table": sectionOffset,
      "Section count": sectionCount
    }
  }
}

export function parseBinary(data: Uint8Array): BinaryInfo {
  if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) return parsePE(data)
  if (data.length >= 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) return parseELF(data)
  return {
    format: "Unknown",
    architecture: "unknown",
    endian: "little",
    entryPoint: 0,
    imageBase: 0,
    sections: [],
    details: {}
  }
}

export interface ExtractedString {
  offset: number
  value: string
}

export function extractStrings(data: Uint8Array, minimum = 5, limit = 5000): ExtractedString[] {
  const result: ExtractedString[] = []
  let start = -1
  for (let i = 0; i <= data.length; i++) {
    const printable = i < data.length && data[i] >= 0x20 && data[i] <= 0x7e
    if (printable && start < 0) start = i
    if (!printable && start >= 0) {
      if (i - start >= minimum) result.push({ offset: start, value: text(data, start, i - start) })
      start = -1
      if (result.length >= limit) break
    }
  }
  return result
}

export function entropyBlocks(data: Uint8Array, blockSize = 512): number[] {
  const result: number[] = []
  for (let offset = 0; offset < data.length; offset += blockSize) {
    result.push(entropy(data, offset, Math.min(blockSize, data.length - offset)))
  }
  return result
}
