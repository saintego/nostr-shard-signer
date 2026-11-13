var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// ../evolustr/packages/core/dist/result.js
var ok = (value) => ({ ok: true, value });
var err = (error2) => ({ ok: false, error: error2 });
var error = (type, message) => err({ type, message });
var attempt = (type, f) => {
  try {
    return ok(f());
  } catch (e) {
    return error(type, e instanceof Error ? e.message : String(e));
  }
};

// ../evolustr/node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new TypeError("expected hash wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
  if (h.outputLen < 1 || h.blockLen < 1)
    throw new Error("hash blockLen / outputLen must be >= 1");
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// ../evolustr/packages/core/dist/bytes.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var utf8 = (text) => encoder.encode(text);
var randomBytes2 = (length) => randomBytes(length);
var toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
var toBase64Url = (bytes) => {
  let binary = "";
  for (const b of bytes)
    binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
var fromBase64Url = (text) => {
  if (!/^[A-Za-z0-9_-]*$/.test(text))
    return null;
  try {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
};

// ../evolustr/node_modules/@noble/ciphers/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle2 = (title) => title ? `"${title}" ` : "";
function abool(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle2(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function anumber2(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle2(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle2(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes2(value, length, title = "") {
  if (isBytes2(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber2(length, "length");
  const bytes = isBytes2(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle2(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function aexists2(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput2(out, instance) {
  abytes2(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function aoutput32(out, instance) {
  aoutput2(out, instance);
  if (!isAligned32(out))
    throw new Error("invalid output, must be aligned");
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean2(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView2(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
var swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n) >>> 0;
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function equalBytes(a, b) {
  a = abytes2(a);
  b = abytes2(b);
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function wrapMacConstructor(keyLen, macCons, fromMsg) {
  const mac = macCons;
  const getArgs = fromMsg || (() => []);
  const macC = (msg, key) => mac(key, ...getArgs(msg)).update(msg).digest();
  const tmp = mac(new Uint8Array(keyLen), ...getArgs(new Uint8Array(0)));
  macC.outputLen = tmp.outputLen;
  macC.blockLen = tmp.blockLen;
  macC.create = (key, ...args) => mac(key, ...args);
  return macC;
}
var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
  function wrappedCipher(key, ...args) {
    abytes2(key, void 0, "key");
    if (params.nonceLength !== void 0) {
      const nonce = args[0];
      abytes2(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
    }
    const tagl = params.tagLength;
    const aadStart = params.nonceLength !== void 0 ? 1 : 0;
    if (!params.withAAD) {
      for (let i = aadStart; i < args.length; i++)
        if (isBytes2(args[i]))
          throw new Error("AAD not supported");
    }
    if (params.withAAD && args[aadStart] !== void 0)
      abytes2(args[aadStart], void 0, "AAD");
    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength, output) => {
      if (output !== void 0) {
        if (fnLength !== 2)
          throw new Error("cipher output not supported");
        abytes2(output, void 0, "output");
      }
    };
    let called = false;
    const wrCipher = {
      encrypt(data, output) {
        if (called)
          throw new Error("cannot encrypt() twice with same key + nonce");
        called = true;
        abytes2(data, void 0, "data");
        checkOutput(cipher.encrypt.length, output);
        return cipher.encrypt(data, output);
      },
      decrypt(data, output) {
        abytes2(data, void 0, "data");
        if (tagl && data.length < tagl)
          throw new Error('"ciphertext" expected length >= tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return cipher.decrypt(data, output);
      }
    };
    return wrCipher;
  }
  Object.assign(wrappedCipher, params);
  return wrappedCipher;
};
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0)
    return new Uint8Array(expectedLength);
  abytes2(out, expectedLength, "output");
  if (onlyAligned && !isAligned32(out))
    throw new Error("invalid output, must be aligned");
  return out;
}
function u64Lengths(dataLength, aadLength, isLE2) {
  anumber2(dataLength);
  anumber2(aadLength);
  abool(isLE2);
  const num = new Uint8Array(16);
  const view = createView2(num);
  view.setBigUint64(0, BigInt(aadLength), isLE2);
  view.setBigUint64(8, BigInt(dataLength), isLE2);
  return num;
}
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes2(bytes));
}

// ../evolustr/node_modules/@noble/ciphers/_polyval.js
var BLOCK_SIZE = 16;
var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
var ZEROS32 = /* @__PURE__ */ u32(ZEROS16);
var POLY = 225;
var mul2 = (s0, s1, s2, s3) => {
  const hiBit = s3 & 1;
  return {
    s3: s2 << 31 | s3 >>> 1,
    s2: s1 << 31 | s2 >>> 1,
    s1: s0 << 31 | s1 >>> 1,
    // NIST SP 800-38D §6.3 applies `V >> 1` and XORs R on carry. In this
    // 4x32-bit split, R = 0xe1 || 0^120 lives in the top byte of s0.
    s0: s0 >>> 1 ^ POLY << 24 & -(hiBit & 1)
    // reduce % poly
  };
};
var swapLE = (n) => (n >>> 0 & 255) << 24 | (n >>> 8 & 255) << 16 | (n >>> 16 & 255) << 8 | n >>> 24 & 255 | 0;
var estimateWindow = (bytes) => {
  if (bytes > 64 * 1024)
    return 8;
  if (bytes > 1024)
    return 4;
  return 2;
};
var GHASH = class {
  // We select bits per window adaptively based on expectedLength
  constructor(key, expectedLength) {
    __publicField(this, "blockLen", BLOCK_SIZE);
    __publicField(this, "outputLen", BLOCK_SIZE);
    __publicField(this, "s0", 0);
    __publicField(this, "s1", 0);
    __publicField(this, "s2", 0);
    __publicField(this, "s3", 0);
    __publicField(this, "finished", false);
    __publicField(this, "destroyed", false);
    __publicField(this, "t");
    __publicField(this, "W");
    __publicField(this, "windowSize");
    abytes2(key, 16, "key");
    key = copyBytes(key);
    const kView = createView2(key);
    let k0 = kView.getUint32(0, false);
    let k1 = kView.getUint32(4, false);
    let k2 = kView.getUint32(8, false);
    let k3 = kView.getUint32(12, false);
    const doubles = [];
    for (let i = 0; i < 128; i++) {
      doubles.push({ s0: swapLE(k0), s1: swapLE(k1), s2: swapLE(k2), s3: swapLE(k3) });
      ({ s0: k0, s1: k1, s2: k2, s3: k3 } = mul2(k0, k1, k2, k3));
    }
    const W = estimateWindow(expectedLength || 1024);
    if (![1, 2, 4, 8].includes(W))
      throw new Error("ghash: invalid window size, expected 2, 4 or 8");
    this.W = W;
    const bits = 128;
    const windows = bits / W;
    const windowSize = this.windowSize = 2 ** W;
    const items = [];
    for (let w = 0; w < windows; w++) {
      for (let byte = 0; byte < windowSize; byte++) {
        let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        for (let j = 0; j < W; j++) {
          const bit = byte >>> W - j - 1 & 1;
          if (!bit)
            continue;
          const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
          s0 ^= d0, s1 ^= d1, s2 ^= d2, s3 ^= d3;
        }
        items.push({ s0, s1, s2, s3 });
      }
    }
    this.t = items;
  }
  _updateBlock(s0, s1, s2, s3) {
    s0 ^= this.s0, s1 ^= this.s1, s2 ^= this.s2, s3 ^= this.s3;
    const { W, t, windowSize } = this;
    let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    const mask = (1 << W) - 1;
    let w = 0;
    for (const num of [s0, s1, s2, s3]) {
      for (let bytePos = 0; bytePos < 4; bytePos++) {
        const byte = num >>> 8 * bytePos & 255;
        for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
          const bit = byte >>> W * bitPos & mask;
          const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
          o0 ^= e0, o1 ^= e1, o2 ^= e2, o3 ^= e3;
          w += 1;
        }
      }
    }
    this.s0 = o0;
    this.s1 = o1;
    this.s2 = o2;
    this.s3 = o3;
  }
  update(data) {
    aexists2(this);
    abytes2(data);
    data = copyBytes(data);
    const b32 = u32(data);
    const blocks = Math.floor(data.length / BLOCK_SIZE);
    const left = data.length % BLOCK_SIZE;
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(swap8IfBE(b32[i * 4 + 0]), swap8IfBE(b32[i * 4 + 1]), swap8IfBE(b32[i * 4 + 2]), swap8IfBE(b32[i * 4 + 3]));
    }
    if (left) {
      ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
      this._updateBlock(swap8IfBE(ZEROS32[0]), swap8IfBE(ZEROS32[1]), swap8IfBE(ZEROS32[2]), swap8IfBE(ZEROS32[3]));
      clean2(ZEROS32);
    }
    return this;
  }
  destroy() {
    this.destroyed = true;
    const { t } = this;
    for (const elm of t) {
      elm.s0 = 0, elm.s1 = 0, elm.s2 = 0, elm.s3 = 0;
    }
  }
  digestInto(out) {
    aexists2(this);
    aoutput32(out, this);
    this.finished = true;
    const { s0, s1, s2, s3 } = this;
    const o32 = u32(out);
    o32[0] = s0;
    o32[1] = s1;
    o32[2] = s2;
    o32[3] = s3;
    if (!isLE)
      swap32IfBE(o32.subarray(0, BLOCK_SIZE / 4));
  }
  digest() {
    const res = new Uint8Array(BLOCK_SIZE);
    this.digestInto(res);
    this.destroy();
    return res;
  }
};
var ghash = /* @__PURE__ */ wrapMacConstructor(16, (key, expectedLength) => new GHASH(key, expectedLength), (msg) => [msg.length]);

// ../evolustr/node_modules/@noble/ciphers/aes.js
var BLOCK_SIZE2 = 16;
var BLOCK_SIZE32 = 4;
var EMPTY_BLOCK = /* @__PURE__ */ new Uint8Array(BLOCK_SIZE2);
var POLY2 = 283;
function validateKeyLength(key) {
  if (![16, 24, 32].includes(key.length))
    throw new Error('"aes key" expected Uint8Array of length 16/24/32, got length=' + key.length);
}
function mul22(n) {
  return n << 1 ^ POLY2 & -(n >> 7);
}
function mul(a, b) {
  let res = 0;
  for (; b > 0; b >>= 1) {
    res ^= a & -(b & 1);
    a = mul22(a);
  }
  return res;
}
var sbox = /* @__PURE__ */ (() => {
  const t = new Uint8Array(256);
  for (let i = 0, x = 1; i < 256; i++, x ^= mul22(x))
    t[i] = x;
  const box = new Uint8Array(256);
  box[0] = 99;
  for (let i = 0; i < 255; i++) {
    let x = t[255 - i];
    x |= x << 8;
    box[t[i]] = (x ^ x >> 4 ^ x >> 5 ^ x >> 6 ^ x >> 7 ^ 99) & 255;
  }
  clean2(t);
  return box;
})();
var rotr32_8 = (n) => n << 24 | n >>> 8;
var rotl32_8 = (n) => n << 8 | n >>> 24;
function genTtable(sbox2, fn) {
  if (sbox2.length !== 256)
    throw new Error("wrong sbox length");
  const T0 = new Uint32Array(256).map((_, j) => fn(sbox2[j]));
  const T1 = T0.map(rotl32_8);
  const T2 = T1.map(rotl32_8);
  const T3 = T2.map(rotl32_8);
  const T01 = new Uint32Array(256 * 256);
  const T23 = new Uint32Array(256 * 256);
  const sbox22 = new Uint16Array(256 * 256);
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const idx = i * 256 + j;
      T01[idx] = T0[i] ^ T1[j];
      T23[idx] = T2[i] ^ T3[j];
      sbox22[idx] = sbox2[i] << 8 | sbox2[j];
    }
  }
  return { sbox: sbox2, sbox2: sbox22, T0, T1, T2, T3, T01, T23 };
}
var tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => mul(s, 3) << 24 | s << 16 | s << 8 | mul(s, 2));
var xPowers = /* @__PURE__ */ (() => {
  const p = new Uint8Array(16);
  for (let i = 0, x = 1; i < 16; i++, x = mul22(x))
    p[i] = x;
  return p;
})();
function expandKeyLE(key) {
  abytes2(key);
  const len = key.length;
  validateKeyLength(key);
  const { sbox2 } = tableEncoding;
  const toClean = [];
  if (!isLE || !isAligned32(key))
    toClean.push(key = copyBytes(key));
  const k32 = swap32IfBE(u32(key));
  const Nk = k32.length;
  const subByte = (n) => applySbox(sbox2, n, n, n, n);
  const xk = new Uint32Array(len + 28);
  xk.set(k32);
  for (let i = Nk; i < xk.length; i++) {
    let t = xk[i - 1];
    if (i % Nk === 0)
      t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
    else if (Nk > 6 && i % Nk === 4)
      t = subByte(t);
    xk[i] = xk[i - Nk] ^ t;
  }
  clean2(...toClean);
  return xk;
}
function apply0123(T01, T23, s0, s1, s2, s3) {
  return T01[s0 << 8 & 65280 | s1 >>> 8 & 255] ^ T23[s2 >>> 8 & 65280 | s3 >>> 24 & 255];
}
function applySbox(sbox2, s0, s1, s2, s3) {
  return sbox2[s0 & 255 | s1 & 65280] | sbox2[s2 >>> 16 & 255 | s3 >>> 16 & 65280] << 16;
}
function encrypt(xk, s0, s1, s2, s3) {
  const { sbox2, T01, T23 } = tableEncoding;
  let k = 0;
  s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t02 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
    const t12 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
    const t22 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
    const t32 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
    s0 = t02, s1 = t12, s2 = t22, s3 = t32;
  }
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function ctr32(xk, isLE2, nonce, src, dst) {
  abytes2(nonce, BLOCK_SIZE2, "nonce");
  abytes2(src);
  dst = getOutput(src.length, dst);
  const ctr = nonce;
  const c32 = u32(ctr);
  const view = createView2(ctr);
  const src32 = u32(src);
  const dst32 = u32(dst);
  const ctrPos = isLE2 ? 0 : 12;
  const srcLen = src.length;
  let ctrNum = view.getUint32(ctrPos, isLE2);
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
    dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
    dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
    dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
    dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
    ctrNum = ctrNum + 1 >>> 0;
    view.setUint32(ctrPos, ctrNum, isLE2);
  }
  const start = BLOCK_SIZE2 * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    swap32IfBE(b32);
    const buf2 = u8(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++)
      dst[i] = src[i] ^ buf2[pos];
    clean2(b32);
  }
  return dst;
}
function computeTag(fn, isLE2, key, data, AAD) {
  const aadLength = AAD ? AAD.length : 0;
  const h = fn.create(key, data.length + aadLength);
  if (AAD)
    h.update(AAD);
  const num = u64Lengths(8 * data.length, 8 * aadLength, isLE2);
  h.update(data);
  h.update(num);
  const res = h.digest();
  clean2(num);
  return res;
}
var gcm = /* @__PURE__ */ wrapCipher({ blockSize: 16, nonceLength: 12, tagLength: 16, withAAD: true, varSizeNonce: true }, function aesgcm(key, nonce, AAD) {
  if (nonce.length < 8)
    throw new Error("aes/gcm: invalid nonce length");
  const tagLength = 16;
  function _computeTag(authKey, tagMask, data) {
    const tag = computeTag(ghash, false, authKey, data, AAD);
    for (let i = 0; i < tagMask.length; i++)
      tag[i] ^= tagMask[i];
    return tag;
  }
  function deriveKeys() {
    const xk = expandKeyLE(key);
    const authKey = EMPTY_BLOCK.slice();
    const counter = EMPTY_BLOCK.slice();
    ctr32(xk, false, counter, counter, authKey);
    if (nonce.length === 12) {
      counter.set(nonce);
    } else {
      const nonceLen = EMPTY_BLOCK.slice();
      const view = createView2(nonceLen);
      view.setBigUint64(8, BigInt(nonce.length * 8), false);
      const g = ghash.create(authKey).update(nonce).update(nonceLen);
      g.digestInto(counter);
      g.destroy();
    }
    const tagMask = ctr32(xk, false, counter, EMPTY_BLOCK);
    return { xk, authKey, counter, tagMask };
  }
  return {
    encrypt(plaintext) {
      const { xk, authKey, counter, tagMask } = deriveKeys();
      const out = new Uint8Array(plaintext.length + tagLength);
      const toClean = [xk, authKey, counter, tagMask];
      if (!isAligned32(plaintext))
        toClean.push(plaintext = copyBytes(plaintext));
      ctr32(xk, false, counter, plaintext, out.subarray(0, plaintext.length));
      const tag = _computeTag(authKey, tagMask, out.subarray(0, out.length - tagLength));
      toClean.push(tag);
      out.set(tag, plaintext.length);
      clean2(...toClean);
      return out;
    },
    decrypt(ciphertext) {
      const { xk, authKey, counter, tagMask } = deriveKeys();
      const toClean = [xk, authKey, tagMask, counter];
      if (!isAligned32(ciphertext))
        toClean.push(ciphertext = copyBytes(ciphertext));
      const data = ciphertext.subarray(0, -tagLength);
      const passedTag = ciphertext.subarray(-tagLength);
      const tag = _computeTag(authKey, tagMask, data);
      toClean.push(tag);
      if (!equalBytes(tag, passedTag)) {
        clean2(...toClean);
        throw new Error("aes-gcm: invalid tag");
      }
      const out = ctr32(xk, false, counter, data);
      clean2(...toClean);
      return out;
    }
  };
});

// ../evolustr/node_modules/@noble/hashes/hmac.js
var _HMAC = class {
  constructor(hash, key) {
    __publicField(this, "oHash");
    __publicField(this, "iHash");
    __publicField(this, "blockLen");
    __publicField(this, "outputLen");
    __publicField(this, "canXOF", false);
    __publicField(this, "finished", false);
    __publicField(this, "destroyed", false);
    ahash(hash);
    abytes(key, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("expected Hash instance");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf2) {
    aexists(this);
    this.iHash.update(buf2);
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf2 = out.subarray(0, this.outputLen);
    this.iHash.digestInto(buf2);
    this.oHash.update(buf2);
    this.oHash.digestInto(buf2);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.canXOF = canXOF;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = /* @__PURE__ */ (() => {
  const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
  hmac_.create = (hash, key) => new _HMAC(hash, key);
  return hmac_;
})();

// ../evolustr/node_modules/@noble/hashes/hkdf.js
var HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
var EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
function expand(hash, prk, info, length = 32, _recycled) {
  ahash(hash);
  anumber(length, "length");
  abytes(prk, void 0, "prk");
  const olen = hash.outputLen;
  if (prk.length < olen)
    throw new Error('"prk" must be at least HashLen octets');
  if (length > 255 * olen)
    throw new Error("Length must be <= 255*HashLen");
  const blocks = Math.ceil(length / olen);
  if (info === void 0)
    info = EMPTY_BUFFER;
  else
    abytes(info, void 0, "info");
  if (!blocks) {
    if (_recycled)
      clean(prk);
    return new Uint8Array();
  }
  const okm = _recycled && blocks === 1 ? prk : new Uint8Array(blocks * olen);
  const { iHash, oHash } = hmac.create(hash, prk);
  const T = _recycled ? prk : new Uint8Array(olen);
  const worker = blocks > 1 ? _recycled?.iHash || hash.create() : void 0;
  for (let counter = 0; counter < blocks - 1; counter++) {
    HKDF_COUNTER[0] = counter + 1;
    const iWork = iHash._cloneInto(worker);
    if (counter)
      iWork.update(T);
    iWork.update(info).update(HKDF_COUNTER).digestInto(T);
    oHash._cloneInto(worker).update(T).digestInto(T);
    okm.set(T, olen * counter);
  }
  HKDF_COUNTER[0] = blocks;
  if (blocks > 1)
    iHash.update(T);
  iHash.update(info).update(HKDF_COUNTER).digestInto(T);
  oHash.update(T).digestInto(T);
  okm.set(T, olen * (blocks - 1));
  iHash.destroy();
  oHash.destroy();
  worker?.destroy();
  if (T !== okm)
    clean(T);
  clean(HKDF_COUNTER);
  if (length === okm.length)
    return okm;
  const res = okm.slice(0, length);
  clean(okm);
  return res;
}
var hkdf = (hash, ikm, salt, info, length) => {
  ahash(hash);
  if (salt === void 0)
    salt = new Uint8Array(hash.outputLen);
  const HMAC = hmac.create(hash, salt).update(ikm);
  return expand(hash, HMAC.digest(), info, length, HMAC);
};

// ../evolustr/node_modules/@noble/hashes/_u64.js
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE2) {
  const h = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE2 ? l : h, isLE2);
  view.setUint32(byteOffset + 4, isLE2 ? h : l, isLE2);
}

// ../evolustr/node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    __publicField(this, "blockLen");
    __publicField(this, "outputLen");
    __publicField(this, "canXOF", false);
    __publicField(this, "padOffset");
    __publicField(this, "isLE");
    // For partial updates less than block size
    __publicField(this, "buffer");
    __publicField(this, "view");
    __publicField(this, "finished", false);
    __publicField(this, "length", 0);
    __publicField(this, "pos", 0);
    __publicField(this, "destroyed", false);
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE2);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// ../evolustr/node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  constructor(outputLen, IV) {
    super(64, outputLen, 8, false);
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    // Numeric initializers matter: starting the fields as `undefined` changes
    // V8's field representation and makes sha256 3x slower (measured).
    __publicField(this, "A", 0);
    __publicField(this, "B", 0);
    __publicField(this, "C", 0);
    __publicField(this, "D", 0);
    __publicField(this, "E", 0);
    __publicField(this, "F", 0);
    __publicField(this, "G", 0);
    __publicField(this, "H", 0);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  constructor() {
    super(32, SHA256_IV);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// ../evolustr/packages/core/dist/crypto.js
var sha2562 = (data) => sha256(data);
var sha256Hex = (data) => toHex(sha2562(typeof data === "string" ? utf8(data) : data));
var hkdf2 = (ikm, info, length = 32, salt) => hkdf(sha256, ikm, salt, utf8(info), length);
var seal = (key, plaintext, aad) => {
  const iv = randomBytes2(12);
  const ct = gcm(key, iv, utf8(aad)).encrypt(plaintext);
  return { iv: toBase64Url(iv), ct: toBase64Url(ct) };
};
var open = (key, sealed, aad) => {
  const iv = fromBase64Url(sealed.iv);
  const ct = fromBase64Url(sealed.ct);
  if (iv === null || iv.length !== 12 || ct === null) {
    return error("malformedCiphertext", "IV or ciphertext is not valid base64url");
  }
  const r = attempt("decryptFailed", () => gcm(key, iv, utf8(aad)).decrypt(ct));
  return r.ok ? ok(r.value) : error("decryptFailed", "Wrong key, wrong AAD, or tampered data");
};

// ../evolustr/packages/core/dist/keys.js
var MASTER_SECRET_LENGTH = 32;
var signerPrfInput = (pubkey) => sha2562(utf8(`evolustr/v1/signer-prf|${pubkey}`));
var signerPasskeyWrapKey = (prfOutput) => hkdf2(prfOutput, "evolustr/v1/signer-passkey-wrap");
var signerSkWrapKey = (secretKey) => hkdf2(secretKey, "evolustr/v1/signer-wrap");
var signerAppKey = (m, appId) => hkdf2(m, `evolustr/v1|app|${appId}`);
var signerId = (m, appId) => toHex(hkdf2(m, `evolustr/v1/signer-id|${appId}`, 8));

// ../evolustr/packages/core/dist/aad.js
var signerWrapAad = (pubkey, signerKey, wrapType, keyId) => `evolustr/v1|signer|${pubkey}|${signerKey}|${wrapType}|${keyId}`;

// ../evolustr/packages/core/dist/tags.js
var VAULT_KIND = 30078;
var PROTECTED_DTAG_PREFIX = "evolustr:";
var signerVaultDTag = (pubkey, signerKey) => `evolustr:v1:signer:${sha256Hex(`evolustr/v1/signer-vault|${pubkey}|${signerKey}`)}`;
var isProtectedDTag = (d) => d.startsWith(PROTECTED_DTAG_PREFIX);

// ../evolustr/packages/core/dist/appId.js
import { decode } from "nostr-tools/nip19";
var isLocalhost = (host) => host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".localhost");
var appIdFromOrigin = (origin, knownNsiteGateways = []) => {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return error("invalidOrigin", "Not a valid origin");
  }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost(host))) {
    return error("insecureOrigin", "Only https: origins (or http: on localhost) can have app data");
  }
  for (const gateway of knownNsiteGateways) {
    const g = gateway.toLowerCase().replace(/^\.+/, "");
    if (!host.endsWith(`.${g}`))
      continue;
    const label = host.slice(0, -(g.length + 1));
    if (label.includes(".") || !label.startsWith("npub1"))
      continue;
    if (isValidNpub(label))
      return ok(`nsite:${label}`);
  }
  return ok(url.origin);
};
var isValidNpub = (value) => {
  try {
    return decode(value).type === "npub";
  } catch {
    return false;
  }
};

// ../evolustr/packages/core/dist/nostr/relays.js
import { SimplePool } from "nostr-tools/pool";
import { matchFilter } from "nostr-tools/filter";

// ../evolustr/packages/core/dist/nostr/verify.js
import { verifyEvent } from "nostr-tools/pure";
var isValidEvent = (event) => {
  const clean3 = JSON.parse(JSON.stringify(event));
  return verifyEvent(clean3);
};

// ../evolustr/packages/core/dist/nostr/relays.js
var toNtFilter = (f) => JSON.parse(JSON.stringify(f));
var withTimeout = (p, ms) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error("timeout")), ms);
  p.then((v) => (clearTimeout(t), resolve(v)), (e) => (clearTimeout(t), reject(e instanceof Error ? e : new Error(String(e)))));
});
var poolRelays = (pool = new SimplePool()) => ({
  query: async (urls, filter, timeoutMs) => {
    const events = /* @__PURE__ */ new Map();
    const idsByRelay = /* @__PURE__ */ new Map();
    const one = async (url) => {
      const ids = /* @__PURE__ */ new Set();
      idsByRelay.set(url, ids);
      try {
        const relay = await withTimeout(pool.ensureRelay(url, { connectionTimeout: timeoutMs }), timeoutMs);
        return await new Promise((resolve) => {
          let settled = false;
          let timer;
          const settle = (answered) => {
            if (settled)
              return;
            settled = true;
            if (timer !== void 0)
              clearTimeout(timer);
            resolve(answered);
          };
          const sub = relay.subscribe([toNtFilter(filter)], {
            onevent: (e) => {
              if (isValidEvent(e)) {
                events.set(e.id, e);
                ids.add(e.id);
              }
            },
            oneose: () => {
              settle(true);
              sub.close();
            },
            onclose: () => settle(false)
          });
          timer = setTimeout(() => {
            settle(false);
            sub.close();
          }, timeoutMs);
        });
      } catch {
        return false;
      }
    };
    const results = await Promise.all(urls.map(async (url) => [url, await one(url)]));
    return {
      events: [...events.values()],
      answered: results.filter(([, ok2]) => ok2).map(([u]) => u),
      failed: results.filter(([, ok2]) => !ok2).map(([u]) => u),
      idsByRelay
    };
  },
  publish: async (urls, event, timeoutMs) => {
    const results = await Promise.all(urls.map(async (url) => {
      try {
        const relay = await withTimeout(pool.ensureRelay(url, { connectionTimeout: timeoutMs }), timeoutMs);
        await withTimeout(relay.publish(event), timeoutMs);
        return [url, "ok"];
      } catch (e) {
        return [url, /time(d)?\s?out/i.test(e instanceof Error ? e.message : String(e)) ? "timeout" : "error"];
      }
    }));
    return {
      accepted: results.filter(([, r]) => r === "ok").map(([u]) => u),
      failed: results.filter(([, r]) => r !== "ok").map(([u]) => u),
      timedOut: results.filter(([, r]) => r === "timeout").map(([u]) => u)
    };
  }
});

// ../evolustr/packages/core/dist/nostr/replaceable.js
var matches = (e, a) => e.pubkey === a.author && e.kind === a.kind && e.tags.some((t) => t[0] === "d" && t[1] === a.d) && isValidEvent(e);
var newest = (events) => [...events].sort((x, y) => y.created_at - x.created_at || (x.id < y.id ? -1 : 1))[0];
var fetchReplaceable = async (relays, urls, address, timeoutMs = 5e3) => {
  const result = await relays.query(urls, { kinds: [address.kind], authors: [address.author], "#d": [address.d] }, timeoutMs);
  const event = newest(result.events.filter((e) => matches(e, address)));
  const complete = result.failed.length === 0;
  if (event !== void 0) {
    const missingOn = result.idsByRelay === void 0 ? [] : result.answered.filter((u) => !result.idsByRelay.get(u)?.has(event.id));
    return { kind: "found", event, complete, missingOn };
  }
  return complete ? { kind: "none" } : { kind: "incomplete" };
};
var publishReplaceable = async (relays, urls, signer, event, timeoutMs = 5e3) => {
  const signed = await signer.signEvent(event);
  const first = await relays.publish(urls, signed, timeoutMs);
  const timedOut = new Set(first.timedOut ?? []);
  const toRetry = first.failed.filter((u) => !timedOut.has(u));
  const retry = toRetry.length === 0 ? { accepted: [], failed: [] } : await relays.publish(toRetry, signed, timeoutMs);
  const accepted = [...first.accepted, ...retry.accepted];
  if (accepted.length === 0)
    throw new Error("No relay accepted the event");
  return { event: signed, accepted, failed: [...first.failed.filter((u) => timedOut.has(u)), ...retry.failed] };
};

// ../evolustr/packages/core/dist/passkeys.js
var buf = (b) => new Uint8Array(b);
var isSynced = (authData) => ((new Uint8Array(authData)[32] ?? 0) & 16) !== 0;
var asBytes = (b) => b === void 0 ? null : new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b));
var webauthnPasskeys = (opts) => {
  const rpId = opts.rpId ?? globalThis.location.hostname;
  return {
    rpId,
    supported: async () => {
      if (typeof PublicKeyCredential === "undefined")
        return false;
      const caps = PublicKeyCredential.getClientCapabilities;
      if (caps === void 0)
        return true;
      return (await caps())["extension:prf"] !== false;
    },
    create: async ({ userId, userName, excludeCredIds, prfInput }) => {
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: buf(randomBytes2(32)),
          rp: { id: rpId, name: opts.rpName },
          user: { id: buf(userId), name: userName, displayName: userName },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
          ],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          excludeCredentials: excludeCredIds.flatMap((id) => {
            const raw = fromBase64Url(id);
            return raw === null ? [] : [{ type: "public-key", id: buf(raw) }];
          }),
          extensions: { prf: { eval: { first: buf(prfInput) } } }
        }
      });
      if (cred === null)
        throw new Error("Passkey creation was cancelled");
      const ext = cred.getClientExtensionResults();
      const response = cred.response;
      return {
        credId: toBase64Url(new Uint8Array(cred.rawId)),
        prfEnabled: ext.prf?.enabled === true || ext.prf?.results?.first !== void 0,
        prfOutput: asBytes(ext.prf?.results?.first),
        synced: typeof response.getAuthenticatorData === "function" ? isSynced(response.getAuthenticatorData()) : false
      };
    },
    get: async ({ allowCredIds, prfInput }) => {
      const cred = await navigator.credentials.get({
        publicKey: {
          challenge: buf(randomBytes2(32)),
          rpId,
          userVerification: "required",
          allowCredentials: allowCredIds.flatMap((id) => {
            const raw = fromBase64Url(id);
            return raw === null ? [] : [{ type: "public-key", id: buf(raw) }];
          }),
          extensions: { prf: { eval: { first: buf(prfInput) } } }
        }
      });
      if (cred === null)
        throw new Error("Passkey use was cancelled");
      const ext = cred.getClientExtensionResults();
      return {
        credId: toBase64Url(new Uint8Array(cred.rawId)),
        prfOutput: asBytes(ext.prf?.results?.first),
        synced: isSynced(cred.response.authenticatorData)
      };
    }
  };
};

// ../evolustr/packages/signer/dist/signer.js
var isRecord = (x) => typeof x === "object" && x !== null;
var parseSignerVault = (json) => {
  let data;
  try {
    data = JSON.parse(json);
  } catch {
    return error("invalidSignerVault", "Not JSON");
  }
  if (!isRecord(data) || data["v"] !== 1 || !Array.isArray(data["wraps"])) {
    return error("invalidSignerVault", "Unknown format");
  }
  const wraps = [];
  for (const w of data["wraps"]) {
    if (!isRecord(w) || typeof w["iv"] !== "string" || typeof w["ct"] !== "string") {
      return error("invalidSignerVault", "Malformed wrap");
    }
    const sealed = { iv: w["iv"], ct: w["ct"] };
    if (w["type"] === "sk")
      wraps.push({ type: "sk", ...sealed });
    else if (w["type"] === "passkey" && typeof w["rpId"] === "string" && typeof w["credId"] === "string") {
      wraps.push({
        type: "passkey",
        rpId: w["rpId"],
        credId: w["credId"],
        ...typeof w["synced"] === "boolean" ? { synced: w["synced"] } : {},
        ...sealed
      });
    } else
      return error("invalidSignerVault", "Unknown wrap type");
  }
  if (wraps.length === 0)
    return error("invalidSignerVault", "The signer vault has no wraps");
  if (wraps.length > MAX_SIGNER_WRAPS)
    return error("invalidSignerVault", "Too many wraps");
  return ok({ v: 1, wraps });
};
var wrapId = (w) => w.type === "sk" ? "sk" : w.credId;
var MAX_SIGNER_WRAPS = 32;
var mergeSignerVaults = (local, fetched) => {
  const byId = /* @__PURE__ */ new Map();
  for (const w of local.wraps)
    byId.set(`${w.type}:${wrapId(w)}`, w);
  for (const w of fetched.wraps) {
    const k = `${w.type}:${wrapId(w)}`;
    if (!byId.has(k) && byId.size < MAX_SIGNER_WRAPS)
      byId.set(k, w);
  }
  return { v: 1, wraps: [...byId.values()] };
};
var PACKAGE_NAME = /^[A-Za-z][\w]*(\.[A-Za-z][\w]*)+$/;
var HEX_PUBKEY = /^[0-9a-f]{64}$/;
var appIdForCaller = (caller, knownNsiteGateways = []) => {
  if (caller.identity === "connection") {
    return HEX_PUBKEY.test(caller.clientPubkey) ? ok(`nip46:${caller.clientPubkey}`) : error("invalidCaller", "Bad client pubkey");
  }
  if ("androidPackage" in caller) {
    return PACKAGE_NAME.test(caller.androidPackage) ? ok(`android:${caller.androidPackage}`) : error("invalidCaller", "Bad package name");
  }
  return appIdFromOrigin(caller.origin, knownNsiteGateways);
};
var isProtectedEvent = (event) => event.kind === VAULT_KIND && event.tags.some((t) => t[0] === "d" && typeof t[1] === "string" && isProtectedDTag(t[1]));
var createEvolustrSigner = (host) => {
  const now = host.now ?? (() => Math.floor(Date.now() / 1e3));
  const random = host.randomBytes ?? randomBytes2;
  const timeoutMs = host.timeoutMs ?? 5e3;
  const allowSk = () => typeof host.allowSkWrap === "function" ? host.allowSkWrap() : host.allowSkWrap !== false;
  let m = null;
  let vault = null;
  let vaultLoaded = false;
  let needsHeal = false;
  let lastEventAt = 0;
  const appIdFor = (caller) => appIdForCaller(caller, host.knownNsiteGateways);
  const fetchVault = async (pubkey) => {
    const f = await fetchReplaceable(host.relays, host.relayUrls, { author: pubkey, kind: VAULT_KIND, d: signerVaultDTag(pubkey, host.signerKey) }, timeoutMs);
    if (f.kind === "none")
      return ok(null);
    if (f.kind === "incomplete")
      return error("relaysUnavailable", "Not every relay answered");
    lastEventAt = Math.max(lastEventAt, f.event.created_at);
    return parseSignerVault(f.event.content);
  };
  const loadVault = async (pubkey) => {
    if (vaultLoaded)
      return ok(vault);
    const fetched = await fetchVault(pubkey);
    if (!fetched.ok && fetched.error.type !== "invalidSignerVault")
      return fetched;
    const copyText = await host.cache?.getVault?.(pubkey) ?? null;
    const copy = copyText === null ? null : parseSignerVault(copyText);
    const local = copy?.ok ? copy.value : null;
    if (local === null) {
      if (!fetched.ok)
        return fetched;
      vault = fetched.value;
    } else if (!fetched.ok || fetched.value === null) {
      vault = local;
      needsHeal = true;
    } else {
      vault = mergeSignerVaults(local, fetched.value);
      const onRelays = new Set(fetched.value.wraps.map((w) => JSON.stringify(w)));
      needsHeal = vault.wraps.some((w) => !onRelays.has(JSON.stringify(w)));
    }
    vaultLoaded = true;
    return ok(vault);
  };
  const publish = async (pubkey, next) => {
    if (!vaultLoaded)
      return error("signerVaultUnknown", "Load the signer vault before changing it");
    const at = Math.max(now(), lastEventAt + 1);
    const signer = {
      getPublicKey: host.getPublicKey,
      signEvent: host.sign,
      nip44Encrypt: () => Promise.reject(new Error("unused")),
      nip44Decrypt: () => Promise.reject(new Error("unused"))
    };
    try {
      await publishReplaceable(host.relays, host.relayUrls, signer, { kind: VAULT_KIND, created_at: at, tags: [["d", signerVaultDTag(pubkey, host.signerKey)]], content: JSON.stringify(next) }, timeoutMs);
    } catch (e) {
      return error("publishFailed", e instanceof Error ? e.message : String(e));
    }
    lastEventAt = at;
    vault = next;
    needsHeal = false;
    await host.cache?.setVault?.(pubkey, JSON.stringify(next));
    return ok(next);
  };
  const sealM = (pubkey, key, w, secret) => {
    const id = w.type === "sk" ? "sk" : w.credId;
    return { ...w, ...seal(key, secret, signerWrapAad(pubkey, host.signerKey, w.type, id)) };
  };
  const openM = (pubkey, w, key) => {
    const r = open(key, w, signerWrapAad(pubkey, host.signerKey, w.type, wrapId(w)));
    return r.ok && r.value.length !== MASTER_SECRET_LENGTH ? error("invalidSignerVault", "Wrong secret length") : r;
  };
  const withWrap = (v, w) => ({
    v: 1,
    wraps: [...(v?.wraps ?? []).filter((x) => !(x.type === w.type && wrapId(x) === wrapId(w))), w]
  });
  const remember = async (pubkey, secret) => {
    m = secret;
    await host.cache?.set(pubkey, secret);
    if (vault !== null)
      await host.cache?.setVault?.(pubkey, JSON.stringify(vault));
  };
  const unlockQuiet = async (pubkey, create) => {
    if (m !== null)
      return ok(true);
    const cached = await host.cache?.get(pubkey);
    if (cached != null && cached.length === MASTER_SECRET_LENGTH) {
      m = cached;
      return ok(true);
    }
    const loaded = await loadVault(pubkey);
    if (!loaded.ok)
      return loaded;
    const sk = host.getSecretKey?.() ?? null;
    if (sk !== null && allowSk()) {
      const skWrap = vault?.wraps.find((w) => w.type === "sk");
      if (skWrap !== void 0) {
        const opened = openM(pubkey, skWrap, signerSkWrapKey(sk));
        if (opened.ok) {
          await remember(pubkey, opened.value);
          return ok(true);
        }
      }
      if (vault === null && create) {
        const fresh = random(MASTER_SECRET_LENGTH);
        const published = await publish(pubkey, withWrap(vault, sealM(pubkey, signerSkWrapKey(sk), { type: "sk" }, fresh)));
        if (!published.ok)
          return published;
        await remember(pubkey, fresh);
        return ok(true);
      }
    }
    return ok(false);
  };
  const unlockWithPasskey = async (pubkey) => {
    const passkeys = host.passkeys;
    const wraps = (vault?.wraps ?? []).filter((w) => w.type === "passkey" && passkeys !== void 0 && w.rpId === passkeys.rpId);
    if (passkeys === void 0 || wraps.length === 0) {
      return error("signerLocked", "No way to unlock this signer's Evolustr key here; enroll a signer passkey");
    }
    await host.ui.requestGesture("unlock");
    let result;
    try {
      result = await passkeys.get({ allowCredIds: wraps.map((w) => w.credId), prfInput: signerPrfInput(pubkey) });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    const wrap = wraps.find((w) => w.credId === result.credId);
    if (wrap === void 0 || result.prfOutput === null)
      return error("passkeyFailed", "The passkey gave no usable result");
    const opened = openM(pubkey, wrap, signerPasskeyWrapKey(result.prfOutput));
    if (!opened.ok)
      return opened;
    await remember(pubkey, opened.value);
    return ok(void 0);
  };
  const ensureM = async () => {
    const pubkey = await host.getPublicKey();
    const quiet = await unlockQuiet(pubkey, true);
    if (!quiet.ok)
      return quiet;
    if (!quiet.value) {
      const viaPasskey = await unlockWithPasskey(pubkey);
      if (!viaPasskey.ok)
        return viaPasskey;
    }
    return m === null ? error("signerLocked", "Locked") : ok({ pubkey, m });
  };
  const capabilities = async (caller) => {
    const appId = appIdFor(caller);
    if (!appId.ok)
      return appId;
    const pubkey = await host.getPublicKey();
    if (m === null)
      await unlockQuiet(pubkey, false);
    if (!vaultLoaded)
      await loadVault(pubkey);
    return ok({
      identity: caller.identity,
      appId: appId.value,
      signerId: m === null ? null : signerId(m, appId.value),
      ready: m !== null,
      signerPasskey: (vault?.wraps ?? []).some((w) => w.type === "passkey"),
      recoverable: (vault?.wraps ?? []).some((w) => w.type === "sk" || w.type === "passkey" && w.synced === true),
      nsecProtected: (vault?.wraps ?? []).some((w) => w.type === "sk")
    });
  };
  const getWrapKey = async (caller) => {
    const appId = appIdFor(caller);
    if (!appId.ok)
      return appId;
    const allowed = await host.ui.confirm({ kind: "appKey", appId: appId.value, identity: caller.identity });
    if (!allowed)
      return error("userRefused", "The user didn't allow this app");
    const unlocked = await ensureM();
    if (!unlocked.ok)
      return unlocked;
    if (!vaultLoaded)
      await loadVault(unlocked.value.pubkey);
    if (needsHeal && vault !== null)
      await publish(unlocked.value.pubkey, vault);
    return ok(signerAppKey(unlocked.value.m, appId.value));
  };
  const enrollPasskey = async () => {
    const passkeys = host.passkeys;
    if (passkeys === void 0)
      return error("noPasskeys", "This signer has no passkey support");
    const pubkey = await host.getPublicKey();
    const loaded = await loadVault(pubkey);
    if (!loaded.ok)
      return loaded;
    const quiet = await unlockQuiet(pubkey, false);
    if (!quiet.ok)
      return quiet;
    if (!await host.ui.confirm({ kind: "enrollPasskey" }))
      return error("userRefused", "Cancelled");
    if (m === null && !allowSk()) {
      const sk = host.getSecretKey?.() ?? null;
      const skWrap = vault?.wraps.find((w) => w.type === "sk");
      if (sk !== null && skWrap !== void 0) {
        const opened = openM(pubkey, skWrap, signerSkWrapKey(sk));
        if (opened.ok)
          await remember(pubkey, opened.value);
      }
    }
    if (m === null && vault !== null) {
      const unlocked = await unlockWithPasskey(pubkey);
      if (!unlocked.ok)
        return error("signerLocked", "Unlock this signer's existing Evolustr key before adding a passkey");
    }
    await host.ui.requestGesture("enrollPasskey");
    let created;
    try {
      created = await passkeys.create({
        userId: sha2562(utf8(`evolustr-signer|${pubkey}`)),
        userName: pubkey.slice(0, 16),
        excludeCredIds: (vault?.wraps ?? []).flatMap((w) => w.type === "passkey" && w.rpId === passkeys.rpId ? [w.credId] : []),
        prfInput: signerPrfInput(pubkey)
      });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    if (!created.prfEnabled)
      return error("prfUnsupported", "This authenticator has no PRF support");
    let prfOutput = created.prfOutput;
    if (prfOutput === null) {
      await host.ui.requestGesture("enrollPasskey");
      prfOutput = (await passkeys.get({ allowCredIds: [created.credId], prfInput: signerPrfInput(pubkey) })).prfOutput;
    }
    if (prfOutput === null)
      return error("prfUnsupported", "The passkey gave no PRF output");
    const secret = m ?? random(MASTER_SECRET_LENGTH);
    let next = withWrap(vault, sealM(pubkey, signerPasskeyWrapKey(prfOutput), { type: "passkey", rpId: passkeys.rpId, credId: created.credId, synced: created.synced }, secret));
    if (!allowSk())
      next = { v: 1, wraps: next.wraps.filter((w) => w.type !== "sk") };
    const published = await publish(pubkey, next);
    if (!published.ok)
      return published;
    await remember(pubkey, secret);
    return ok(void 0);
  };
  const handle = async (method, _params, caller) => {
    switch (method) {
      case "evolustr_capabilities":
        return capabilities(caller);
      case "evolustr_get_wrap_key": {
        const key = await getWrapKey(caller);
        return key.ok ? ok(toBase64Url(key.value)) : key;
      }
      case "evolustr_enroll_passkey":
        return enrollPasskey();
      default:
        return error("unknownMethod", `Unknown method ${method}`);
    }
  };
  const lock = async () => {
    const pubkey = await host.getPublicKey().catch(() => null);
    m = null;
    vault = null;
    vaultLoaded = false;
    needsHeal = false;
    if (pubkey !== null)
      await host.cache?.remove(pubkey);
  };
  return { handle, capabilities, getWrapKey, enrollPasskey, isProtectedEvent, appIdFor, lock };
};
export {
  createEvolustrSigner,
  fromBase64Url,
  isProtectedEvent,
  poolRelays,
  toBase64Url,
  webauthnPasskeys
};
