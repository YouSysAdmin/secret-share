// Client-side AES-256-GCM
// A key is generated in the browser.
// A wire format for the stored blob is base64(iv(12) || ciphertext+tag),
// the fragment key is base64url of a raw 32-byte key.

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

// encryptToPayload returns { ciphertext, key }: ciphertext = base64(iv||ct)
// for the server to store opaquely
// key = base64url(rawKey) for the URL fragment.
export async function encryptToPayload(plaintext) {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext),
  );
  const ct = new Uint8Array(ctBuf);
  const combined = new Uint8Array(iv.length + ct.length);
  combined.set(iv, 0);
  combined.set(ct, iv.length);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { ciphertext: bytesToB64(combined), key: b64url(rawKey) };
}

// decryptFromPayload reverses encryptToPayload.
// Throws if the key is wrong or the blob was tampered with (GCM auth failure).
export async function decryptFromPayload(ciphertextB64, keyB64url) {
  const combined = b64ToBytes(ciphertextB64);
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);
  const key = await crypto.subtle.importKey(
    "raw",
    b64urlToBytes(keyB64url),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(ptBuf);
}
