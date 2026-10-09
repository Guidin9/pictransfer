// Self-test for src/qr.ts: known-answer vectors plus a round-trip through an
// independent matrix reader. Run: node dev/qr-selftest.ts
import {
  alignmentPositions,
  dataBytes,
  dataCodewords,
  encodeQr,
  formatBits,
  rsDivisor,
  rsRemainder,
  versionBits,
} from "../src/qr.ts";

let failed = 0;
function eq(name: string, got: unknown, want: unknown): void {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) {
    failed++;
    console.log(`FAIL ${name}\n  got  ${g}\n  want ${w}`);
  } else console.log(`ok   ${name}`);
}

// ISO 18004 / thonky.com "HELLO WORLD" 1-M.
const hw = dataBytes("HELLO WORLD", 1, "M");
eq("HELLO WORLD 1-M data", hw, [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]);
eq("HELLO WORLD 1-M ecc", rsRemainder(hw ?? [], rsDivisor(10)), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
// Format strings (ISO 18004 Annex C table).
eq("format M/6", formatBits("M", 6).toString(2).padStart(15, "0"), "100111110010111");
eq("format M/0", formatBits("M", 0).toString(2).padStart(15, "0"), "101010000010010");
eq("format L/0", formatBits("L", 0).toString(2).padStart(15, "0"), "111011111000100");
eq("format L/4", formatBits("L", 4).toString(2).padStart(15, "0"), "110011000101111");
eq("format M/7", formatBits("M", 7).toString(2).padStart(15, "0"), "100101010100000");
// Version information (Annex D).
eq("version 7", versionBits(7).toString(2).padStart(18, "0"), "000111110010010100");
eq("version 40", versionBits(40).toString(2).padStart(18, "0"), "101000110001101001");
// Alignment positions (Annex E).
eq("align v7", alignmentPositions(7), [6, 22, 38]);
eq("align v32", alignmentPositions(32), [6, 34, 60, 86, 112, 138]);
eq("align v40", alignmentPositions(40), [6, 30, 58, 86, 114, 142, 170]);
// Capacities (Table 7, data codewords).
eq("cap 1-M", dataCodewords(1, "M"), 16);
eq("cap 10-M", dataCodewords(10, "M"), 216);
eq("cap 40-M", dataCodewords(40, "M"), 2334);
eq("cap 40-L", dataCodewords(40, "L"), 2956);

// --- Independent reader: format -> unmask -> zigzag -> deinterleave -> parse.
const ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
function read(mod: boolean[][]): string {
  const size = mod.length;
  const ver = (size - 17) / 4;
  const get = (x: number, y: number) => mod[y]?.[x] ?? false;
  let f = 0;
  for (let i = 0; i < 15; i++) {
    // second copy: bits 0-7 at (size-1-i, 8), bits 8-14 at (8, size-15+i)
    const b = i < 8 ? get(size - 1 - i, 8) : get(8, size - 15 + i);
    f |= (b ? 1 : 0) << i;
  }
  f ^= 0x5412;
  const mask = (f >>> 10) & 7;
  const eccBits = (f >>> 13) & 3;
  const ecc = eccBits === 1 ? "L" : "M";
  // function-module map rebuilt from scratch
  const fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const mark = (x: number, y: number) => {
    if (x >= 0 && y >= 0 && x < size && y < size) (fn[y] as boolean[])[x] = true;
  };
  for (let y = 0; y < 9; y++) for (let x = 0; x < 9; x++) mark(x, y);
  for (let y = 0; y < 9; y++) for (let x = size - 8; x < size; x++) mark(x, y);
  for (let y = size - 8; y < size; y++) for (let x = 0; x < 9; x++) mark(x, y);
  for (let i = 0; i < size; i++) {
    mark(6, i);
    mark(i, 6);
  }
  const al = alignmentPositions(ver);
  for (const a of al)
    for (const b of al) {
      if ((a < 9 && b < 9) || (a < 9 && b > size - 9) || (a > size - 9 && b < 9)) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) mark(a + dx, b + dy);
    }
  if (ver >= 7)
    for (let i = 0; i < 18; i++) {
      mark(size - 11 + (i % 3), Math.floor(i / 3));
      mark(Math.floor(i / 3), size - 11 + (i % 3));
    }
  const masks = [
    (x: number, y: number) => (x + y) % 2 === 0,
    (_x: number, y: number) => y % 2 === 0,
    (x: number) => x % 3 === 0,
    (x: number, y: number) => (x + y) % 3 === 0,
    (x: number, y: number) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
    (x: number, y: number) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x: number, y: number) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x: number, y: number) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];
  const bits: number[] = [];
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let k = 0; k < size; k++) {
      const y = upward ? size - 1 - k : k;
      for (const x of [col, col - 1]) {
        if (fn[y]?.[x]) continue;
        const m = masks[mask] as (x: number, y: number) => boolean;
        bits.push((get(x, y) !== m(x, y)) ? 1 : 0);
      }
    }
    upward = !upward;
  }
  const cws: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) cws.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  // deinterleave data codewords
  const nData = dataCodewords(ver, ecc);
  const blocksTbl: Record<string, number[]> = {
    L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  };
  const nb = blocksTbl[ecc]?.[ver] ?? 1;
  const shortData = Math.floor(nData / nb);
  const nLong = nData % nb;
  const blocks: number[][] = Array.from({ length: nb }, () => []);
  let p = 0;
  for (let i = 0; i < shortData + 1; i++)
    for (let b = 0; b < nb; b++) {
      const len = shortData + (b >= nb - nLong ? 1 : 0);
      if (i < len) (blocks[b] as number[]).push(cws[p++] ?? 0);
    }
  const data = blocks.flat();
  const dbits = data.flatMap((v) => v.toString(2).padStart(8, "0").split("").map(Number));
  let q = 0;
  const take = (n: number) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | (dbits[q++] ?? 0);
    return v;
  };
  const mode = take(4);
  if (mode === 2) {
    const n = take(ver <= 9 ? 9 : ver <= 26 ? 11 : 13);
    let s = "";
    for (let i = 0; i + 1 < n; i += 2) {
      const v = take(11);
      s += ALNUM[Math.floor(v / 45)] + (ALNUM[v % 45] ?? "");
    }
    if (n % 2) s += ALNUM[take(6)];
    return s;
  }
  if (mode === 4) {
    const n = take(ver <= 9 ? 8 : 16);
    const by = new Uint8Array(n);
    for (let i = 0; i < n; i++) by[i] = take(8);
    return new TextDecoder().decode(by);
  }
  return `<mode ${mode}>`;
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
let seed = 7;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
for (const len of [10, 100, 380, 420, 600, 1200, 1800]) {
  let s = "WARP1:";
  for (let i = 0; i < len; i++) s += B32[rnd() % 32];
  for (const mask of [undefined, 0, 3, 5, 7]) {
    const q = encodeQr(s, "M", mask);
    eq(`round-trip alnum len=${len} v${q.version} mask=${q.mask}`, read(q.modules) === s && q.alnum, true);
  }
}
const q = encodeQr("Merhaba dünya — ğüşiöç", "M");
eq(`round-trip byte v${q.version}`, read(q.modules), "Merhaba dünya — ğüşiöç");

if (failed) {
  console.log(`${failed} FAILED`);
  process.exit(1);
}
console.log("all QR self-tests passed");
