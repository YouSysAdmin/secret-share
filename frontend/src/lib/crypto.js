// Client-side AES-256-GCM
// A key is generated in the browser (or derived from a passphrase).
// Wire formats (always opaque to the server):
//   key mode:        iv(12) || ciphertext+tag
//   passphrase mode: magic "SSP1"(4) || salt(16) || iterations(4, uint32 BE) || iv(12) || ciphertext+tag
// Text secrets store the blob as base64; files store/ship the raw bytes.
// The fragment key is base64url of a raw 32-byte key.

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64url(bytes) {
  return bytesToB64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return b64ToBytes(s);
}

// --- binary primitives (files use these directly; text wraps them in base64) ---

// encryptBytes returns { blob: Uint8Array(iv||ct), key: base64url(rawKey) }.
export async function encryptBytes(plainBytes) {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBytes,
  );
  const ct = new Uint8Array(ctBuf);
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv, 0);
  blob.set(ct, iv.length);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { blob, key: b64url(rawKey) };
}

// decryptBytes reverses encryptBytes. Throws if the key is wrong or the blob
// was tampered with (GCM auth failure).
export async function decryptBytes(blob, keyB64url) {
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  const key = await crypto.subtle.importKey(
    "raw",
    b64urlToBytes(keyB64url),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(ptBuf);
}

// --- passphrase mode ---
// The AES key is derived from a passphrase (PBKDF2-SHA256) instead of riding
// the URL fragment; the passphrase travels out-of-band. Iterations are stored
// per-blob so the count can be raised later without breaking old links.

const PASS_MAGIC = [0x53, 0x53, 0x50, 0x31]; // "SSP1"
const PASS_ITERATIONS = 600000; // OWASP-recommended floor for PBKDF2-SHA256

async function deriveKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// encryptBytesWithPassphrase returns the self-describing blob; there is no
// fragment key - the recipient must know the passphrase.
export async function encryptBytesWithPassphrase(plainBytes, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, PASS_ITERATIONS);
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBytes,
  );
  const ct = new Uint8Array(ctBuf);
  const blob = new Uint8Array(4 + 16 + 4 + 12 + ct.length);
  blob.set(PASS_MAGIC, 0);
  blob.set(salt, 4);
  new DataView(blob.buffer).setUint32(20, PASS_ITERATIONS, false);
  blob.set(iv, 24);
  blob.set(ct, 36);
  return blob;
}

// isPassphraseBlob reports whether raw bytes carry the passphrase-mode magic.
export function isPassphraseBlob(blob) {
  return blob.length > 36 && PASS_MAGIC.every((v, i) => blob[i] === v);
}

// decryptBytesWithPassphrase reverses encryptBytesWithPassphrase. Throws on a
// wrong passphrase or a tampered blob (GCM auth failure).
export async function decryptBytesWithPassphrase(blob, passphrase) {
  if (!isPassphraseBlob(blob)) {
    throw new Error("not a passphrase-protected secret");
  }
  const salt = blob.slice(4, 20);
  const iterations = new DataView(
    blob.buffer,
    blob.byteOffset,
    blob.byteLength,
  ).getUint32(20, false);
  if (iterations < 1 || iterations > 10000000) {
    throw new Error("corrupted secret blob");
  }
  const iv = blob.slice(24, 36);
  const ct = blob.slice(36);
  const key = await deriveKey(passphrase, salt, iterations);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(ptBuf);
}

// --- text secrets (base64 wire format, as stored via the JSON API) ---

// encryptToPayload returns { ciphertext, key }: ciphertext = base64(iv||ct)
// for the server to store opaquely, key = base64url(rawKey) for the fragment.
export async function encryptToPayload(plaintext) {
  const { blob, key } = await encryptBytes(enc.encode(plaintext));
  return { ciphertext: bytesToB64(blob), key };
}

// decryptFromPayload reverses encryptToPayload.
export async function decryptFromPayload(ciphertextB64, keyB64url) {
  return dec.decode(await decryptBytes(b64ToBytes(ciphertextB64), keyB64url));
}

// encryptWithPassphrase returns { ciphertext } only - no fragment key.
export async function encryptWithPassphrase(plaintext, passphrase) {
  const blob = await encryptBytesWithPassphrase(enc.encode(plaintext), passphrase);
  return { ciphertext: bytesToB64(blob) };
}

// isPassphrasePayload reports whether a stored base64 blob was made by
// encryptWithPassphrase (checks the magic prefix).
export function isPassphrasePayload(ciphertextB64) {
  try {
    return isPassphraseBlob(b64ToBytes(ciphertextB64));
  } catch {
    return false;
  }
}

// decryptWithPassphrase reverses encryptWithPassphrase.
export async function decryptWithPassphrase(ciphertextB64, passphrase) {
  return dec.decode(
    await decryptBytesWithPassphrase(b64ToBytes(ciphertextB64), passphrase),
  );
}

// --- file payloads ---
// A file is packed as [4-byte BE header length][header JSON][content bytes]
// BEFORE encryption, so the filename/type are as secret as the content.

// packFilePayload serializes name/type/content into one plaintext buffer.
export function packFilePayload(name, type, contentBytes) {
  const header = enc.encode(JSON.stringify({ name, type }));
  const packed = new Uint8Array(4 + header.length + contentBytes.length);
  new DataView(packed.buffer).setUint32(0, header.length, false);
  packed.set(header, 4);
  packed.set(contentBytes, 4 + header.length);
  return packed;
}

// unpackFilePayload reverses packFilePayload -> { name, type, bytes }.
export function unpackFilePayload(packed) {
  const headerLen = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  ).getUint32(0, false);
  if (headerLen < 2 || headerLen > packed.length - 4) {
    throw new Error("corrupted file payload");
  }
  const header = JSON.parse(dec.decode(packed.slice(4, 4 + headerLen)));
  return {
    name: typeof header.name === "string" ? header.name : "download",
    type: typeof header.type === "string" ? header.type : "application/octet-stream",
    bytes: packed.slice(4 + headerLen),
  };
}
