import assert from "node:assert/strict"
import test from "node:test"
import { entropy, extractStrings, parseBinary, parseELF, parsePE } from "../src/parser.js"

function pe64(): Uint8Array {
  const data = new Uint8Array(0x400)
  const v = new DataView(data.buffer)
  v.setUint16(0, 0x5a4d, true)
  v.setUint32(0x3c, 0x80, true)
  v.setUint32(0x80, 0x00004550, true)
  v.setUint16(0x84, 0x8664, true)
  v.setUint16(0x86, 1, true)
  v.setUint16(0x94, 0xf0, true)
  v.setUint16(0x98, 0x20b, true)
  v.setUint32(0xa8, 0x1000, true)
  v.setBigUint64(0xb0, 0x140000000n, true)
  v.setUint32(0xb8, 0x1000, true)
  v.setUint32(0xbc, 0x200, true)
  v.setUint32(0xd0, 0x3000, true)
  v.setUint16(0xdc, 3, true)
  const section = 0x188
  data.set(new TextEncoder().encode(".text"), section)
  v.setUint32(section + 8, 0x120, true)
  v.setUint32(section + 12, 0x1000, true)
  v.setUint32(section + 16, 0x200, true)
  v.setUint32(section + 20, 0x200, true)
  v.setUint32(section + 36, 0x60000020, true)
  data.fill(0x90, 0x200, 0x400)
  return data
}

function elf64(): Uint8Array {
  const data = new Uint8Array(0x300)
  const v = new DataView(data.buffer)
  data.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0])
  v.setUint16(16, 2, true)
  v.setUint16(18, 62, true)
  v.setBigUint64(24, 0x401000n, true)
  v.setBigUint64(40, 0x100n, true)
  v.setUint16(58, 64, true)
  v.setUint16(60, 2, true)
  v.setUint16(62, 1, true)
  const strings = 0x200
  data.set(new TextEncoder().encode("\0.shstrtab\0"), strings)
  const shstr = 0x140
  v.setUint32(shstr, 1, true)
  v.setUint32(shstr + 4, 3, true)
  v.setBigUint64(shstr + 24, BigInt(strings), true)
  v.setBigUint64(shstr + 32, 11n, true)
  return data
}

test("parses PE32+ headers and sections", () => {
  const info = parsePE(pe64())
  assert.equal(info.format, "PE32+")
  assert.equal(info.architecture, "x86-64")
  assert.equal(info.entryPoint, 0x140001000)
  assert.equal(info.sections[0].name, ".text")
  assert.equal(info.sections[0].flags, "XR")
})

test("parses ELF64 headers and names", () => {
  const info = parseELF(elf64())
  assert.equal(info.format, "ELF64")
  assert.equal(info.architecture, "x86-64")
  assert.equal(info.entryPoint, 0x401000)
  assert.equal(info.sections[1].name, ".shstrtab")
})

test("detects unknown binaries", () => {
  assert.equal(parseBinary(new Uint8Array([1, 2, 3])).format, "Unknown")
})

test("extracts printable strings with offsets", () => {
  const data = new TextEncoder().encode("\0hello world\0xx\0binary-canvas\0")
  assert.deepEqual(extractStrings(data, 5), [
    { offset: 1, value: "hello world" },
    { offset: 16, value: "binary-canvas" }
  ])
})

test("computes entropy", () => {
  assert.equal(entropy(new Uint8Array(256)), 0)
  const uniform = Uint8Array.from({ length: 256 }, (_, i) => i)
  assert.equal(entropy(uniform), 8)
})

test("rejects truncated structured binaries", () => {
  assert.throws(() => parsePE(new Uint8Array([0x4d, 0x5a])))
  assert.throws(() => parseELF(new Uint8Array([0x7f, 0x45, 0x4c, 0x46])))
})
