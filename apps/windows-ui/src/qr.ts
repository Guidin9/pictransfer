// Minimal QR Code encoder (ISO/IEC 18004), model 2, versions 1-40.
// Alphanumeric mode when the text allows it (the pairing text is
// "WARP1:" + base32, protocol §5.2), byte mode (UTF-8) otherwise.
// No dependencies; output is a boolean module matrix.

export type Ecc = "L" | "M";

// Index 0 unused; per version 1..40.
const ECC_PER_BLOCK: Record<Ecc, number[]> = {
  L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
};
const NUM_BLOCKS: Record<Ecc, number[]> = {
  L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
};
const ECC_FORMAT_BITS: Record<Ecc, number> = { L: 1, M: 0 };
const ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

const at = (a: readonly number[], i: number): number => a[i] ?? 0;

export function rawDataModules(ver: number): number {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

export function dataCodewords(ver: number, ecc: Ecc): number {
  return Math.floor(rawDataModules(ver) / 8) - at(ECC_PER_BLOCK[ecc], ver) * at(NUM_BLOCKS[ecc], ver);
}

class Bits {
  readonly b: number[] = [];
  put(val: number, len: number): void {
    for (let i = len - 1; i >= 0; i--) this.b.push((val >>> i) & 1);
  }
}

function isAlnum(s: string): boolean {
  for (const c of s) if (!ALNUM.includes(c)) return false;
  return true;
}

function countBits(alnum: boolean, ver: number): number {
  if (alnum) return ver <= 9 ? 9 : ver <= 26 ? 11 : 13;
  return ver <= 9 ? 8 : 16;
}

function encodeSegment(text: string, ver: number): Bits {
  const bits = new Bits();
  if (isAlnum(text)) {
    bits.put(0b0010, 4);
    bits.put(text.length, countBits(true, ver));
    let i = 0;
    for (; i + 1 < text.length; i += 2) {
      bits.put(ALNUM.indexOf(text.charAt(i)) * 45 + ALNUM.indexOf(text.charAt(i + 1)), 11);
    }
    if (i < text.length) bits.put(ALNUM.indexOf(text.charAt(i)), 6);
  } else {
    const bytes = new TextEncoder().encode(text);
    bits.put(0b0100, 4);
    bits.put(bytes.length, countBits(false, ver));
    for (const by of bytes) bits.put(by, 8);
  }
  return bits;
}

// GF(256), polynomial 0x11D.
function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

export function rsDivisor(degree: number): number[] {
  const r: number[] = new Array<number>(degree).fill(0);
  r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      r[j] = gfMul(at(r, j), root);
      if (j + 1 < degree) r[j] = at(r, j) ^ at(r, j + 1);
    }
    root = gfMul(root, 0x02);
  }
  return r;
}

export function rsRemainder(data: readonly number[], div: readonly number[]): number[] {
  const r: number[] = new Array<number>(div.length).fill(0);
  for (const b of data) {
    const factor = b ^ (r.shift() ?? 0);
    r.push(0);
    for (let i = 0; i < div.length; i++) r[i] = at(r, i) ^ gfMul(at(div, i), factor);
  }
  return r;
}

/** Data codewords (with terminator and padding) for `text` at `ver`. */
export function dataBytes(text: string, ver: number, ecc: Ecc): number[] | null {
  const cap = dataCodewords(ver, ecc) * 8;
  const bits = encodeSegment(text, ver);
  if (bits.b.length > cap) return null;
  bits.put(0, Math.min(4, cap - bits.b.length));
  bits.put(0, (8 - (bits.b.length % 8)) % 8);
  for (let pad = 0xec; bits.b.length < cap; pad ^= 0xec ^ 0x11) bits.put(pad, 8);
  const out: number[] = [];
  for (let i = 0; i < bits.b.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | at(bits.b, i + j);
    out.push(v);
  }
  return out;
}

function interleave(data: readonly number[], ver: number, ecc: Ecc): number[] {
  const numBlocks = at(NUM_BLOCKS[ecc], ver);
  const eccLen = at(ECC_PER_BLOCK[ecc], ver);
  const raw = Math.floor(rawDataModules(ver) / 8);
  const numShort = numBlocks - (raw % numBlocks);
  const shortLen = Math.floor(raw / numBlocks);
  const div = rsDivisor(eccLen);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const len = shortLen - eccLen + (i < numShort ? 0 : 1);
    const dat = data.slice(k, k + len);
    k += len;
    const e = rsRemainder(dat, div);
    if (i < numShort) dat.push(0);
    blocks.push(dat.concat(e));
  }
  const out: number[] = [];
  const width = blocks[0]?.length ?? 0;
  for (let i = 0; i < width; i++) {
    blocks.forEach((blk, j) => {
      if (i !== shortLen - eccLen || j >= numShort) out.push(at(blk, i));
    });
  }
  return out;
}

export function alignmentPositions(ver: number): number[] {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2;
  const step = Math.floor((ver * 8 + n * 3 + 5) / (n * 4 - 4)) * 2;
  const out = [6];
  for (let pos = ver * 4 + 10; out.length < n; pos -= step) out.splice(1, 0, pos);
  return out;
}

export function formatBits(ecc: Ecc, mask: number): number {
  const data = (ECC_FORMAT_BITS[ecc] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

export function versionBits(ver: number): number {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (ver << 12) | rem;
}

const MASKS: ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

class Grid {
  readonly m: boolean[][];
  readonly fn: boolean[][];
  readonly size: number;
  constructor(size: number) {
    this.size = size;
    this.m = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }
  get(x: number, y: number): boolean {
    return this.m[y]?.[x] ?? false;
  }
  isFn(x: number, y: number): boolean {
    return this.fn[y]?.[x] ?? false;
  }
  set(x: number, y: number, dark: boolean, fn = true): void {
    const row = this.m[y];
    const frow = this.fn[y];
    if (!row || !frow || x < 0 || x >= this.size) return;
    row[x] = dark;
    if (fn) frow[x] = true;
  }
}

function drawFunctionPatterns(g: Grid, ver: number, ecc: Ecc): void {
  const s = g.size;
  for (let i = 0; i < s; i++) {
    g.set(6, i, i % 2 === 0);
    g.set(i, 6, i % 2 === 0);
  }
  const finder = (cx: number, cy: number) => {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < s && y >= 0 && y < s) g.set(x, y, d !== 2 && d !== 4);
      }
  };
  finder(3, 3);
  finder(s - 4, 3);
  finder(3, s - 4);
  const al = alignmentPositions(ver);
  const n = al.length;
  for (let i = 0; i < n; i++)
    for (let j = 0; j < n; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
      const cx = at(al, i);
      const cy = at(al, j);
      for (let dy = -2; dy <= 2; dy++)
        for (let dx = -2; dx <= 2; dx++) g.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  drawFormat(g, ecc, 0); // reserve; real bits after masking
  if (ver >= 7) {
    const bits = versionBits(ver);
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) !== 0;
      const a = s - 11 + (i % 3);
      const b = Math.floor(i / 3);
      g.set(a, b, bit);
      g.set(b, a, bit);
    }
  }
}

function drawFormat(g: Grid, ecc: Ecc, mask: number): void {
  const bits = formatBits(ecc, mask);
  const bit = (i: number) => ((bits >>> i) & 1) !== 0;
  const s = g.size;
  for (let i = 0; i <= 5; i++) g.set(8, i, bit(i));
  g.set(8, 7, bit(6));
  g.set(8, 8, bit(7));
  g.set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) g.set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) g.set(s - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) g.set(8, s - 15 + i, bit(i));
  g.set(8, s - 8, true); // dark module
}

function drawCodewords(g: Grid, cw: readonly number[]): void {
  const s = g.size;
  let i = 0;
  for (let right = s - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < s; vert++)
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? s - 1 - vert : vert;
        if (!g.isFn(x, y) && i < cw.length * 8) {
          g.set(x, y, ((at(cw, i >>> 3) >>> (7 - (i & 7))) & 1) !== 0, false);
          i++;
        }
      }
  }
}

function applyMask(g: Grid, mask: number): void {
  const f = MASKS[mask];
  if (!f) return;
  for (let y = 0; y < g.size; y++)
    for (let x = 0; x < g.size; x++) if (!g.isFn(x, y) && f(x, y)) g.set(x, y, !g.get(x, y), false);
}

function penalty(g: Grid): number {
  const s = g.size;
  let p = 0;
  const line = (get: (i: number) => boolean) => {
    let run = 1;
    for (let i = 1; i <= s; i++) {
      if (i < s && get(i) === get(i - 1)) run++;
      else {
        if (run >= 5) p += run - 2;
        run = 1;
      }
    }
    const pat = [true, false, true, true, true, false, true];
    for (let i = -4; i < s; i++) {
      const v = (k: number) => (k >= 0 && k < s ? get(k) : false);
      if (!pat.every((d, k) => v(i + k) === d)) continue;
      const lightBefore = [1, 2, 3, 4].every((k) => !v(i - k));
      const lightAfter = [7, 8, 9, 10].every((k) => !v(i + k));
      if (lightBefore || lightAfter) p += 40;
    }
  };
  for (let y = 0; y < s; y++) line((x) => g.get(x, y));
  for (let x = 0; x < s; x++) line((y) => g.get(x, y));
  let dark = 0;
  for (let y = 0; y < s; y++)
    for (let x = 0; x < s; x++) {
      const c = g.get(x, y);
      if (c) dark++;
      if (x + 1 < s && y + 1 < s && c === g.get(x + 1, y) && c === g.get(x, y + 1) && c === g.get(x + 1, y + 1)) p += 3;
    }
  const total = s * s;
  p += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
  return p;
}

export interface QrCode {
  version: number;
  size: number;
  mask: number;
  alnum: boolean;
  modules: boolean[][];
}

export function encodeQr(text: string, ecc: Ecc = "M", forceMask?: number): QrCode {
  for (let ver = 1; ver <= 40; ver++) {
    const data = dataBytes(text, ver, ecc);
    if (!data) continue;
    const cw = interleave(data, ver, ecc);
    const build = (mask: number): Grid => {
      const g = new Grid(ver * 4 + 17);
      drawFunctionPatterns(g, ver, ecc);
      drawCodewords(g, cw);
      applyMask(g, mask);
      drawFormat(g, ecc, mask);
      return g;
    };
    let bestMask = forceMask ?? 0;
    if (forceMask === undefined) {
      let best = Infinity;
      for (let m = 0; m < 8; m++) {
        const pen = penalty(build(m));
        if (pen < best) {
          best = pen;
          bestMask = m;
        }
      }
    }
    const g = build(bestMask);
    return { version: ver, size: g.size, mask: bestMask, alnum: isAlnum(text), modules: g.m };
  }
  throw new Error("qr: text too long");
}

export const __test = { interleave };
