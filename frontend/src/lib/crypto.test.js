import { describe, it, expect } from "vitest";
import {
  encryptToPayload,
  decryptFromPayload,
  encryptWithPassphrase,
  decryptWithPassphrase,
  isPassphrasePayload,
  encryptBytes,
  decryptBytes,
  encryptBytesWithPassphrase,
  decryptBytesWithPassphrase,
  packFilePayload,
  unpackFilePayload,
} from "./crypto.js";

describe("crypto", () => {
  it("round-trips plaintext", async () => {
    const plain = "hunter2 - with unicode ✓ and\nnewlines";
    const { ciphertext, key } = await encryptToPayload(plain);
    expect(ciphertext).toBeTruthy();
    expect(key).toBeTruthy();
    const out = await decryptFromPayload(ciphertext, key);
    expect(out).toBe(plain);
  });

  it("fails to decrypt with the wrong key", async () => {
    const { ciphertext } = await encryptToPayload("secret");
    const { key: otherKey } = await encryptToPayload("unrelated");
    await expect(decryptFromPayload(ciphertext, otherKey)).rejects.toBeTruthy();
  });

  it("produces a url-safe fragment key", async () => {
    const { key } = await encryptToPayload("x");
    expect(key).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("passphrase crypto", () => {
  it("round-trips plaintext with a passphrase", async () => {
    const plain = "hunter2 - with unicode ✓ and\nnewlines";
    const { ciphertext } = await encryptWithPassphrase(plain, "correct horse");
    expect(ciphertext).toBeTruthy();
    const out = await decryptWithPassphrase(ciphertext, "correct horse");
    expect(out).toBe(plain);
  });

  it("fails to decrypt with the wrong passphrase", async () => {
    const { ciphertext } = await encryptWithPassphrase("secret", "right");
    await expect(decryptWithPassphrase(ciphertext, "wrong")).rejects.toBeTruthy();
  });

  it("tags passphrase payloads with the magic prefix", async () => {
    const { ciphertext } = await encryptWithPassphrase("x", "pw");
    expect(isPassphrasePayload(ciphertext)).toBe(true);
    const { ciphertext: plainKeyBlob } = await encryptToPayload("x");
    expect(isPassphrasePayload(plainKeyBlob)).toBe(false);
  });

  it("rejects a key-mode blob passed to the passphrase decryptor", async () => {
    const { ciphertext } = await encryptToPayload("x");
    await expect(decryptWithPassphrase(ciphertext, "pw")).rejects.toThrow(
      /not a passphrase-protected secret/,
    );
  });
});

describe("file crypto", () => {
  const content = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);

  it("packs and unpacks a file payload", () => {
    const packed = packFilePayload("notes.txt", "text/plain", content);
    const out = unpackFilePayload(packed);
    expect(out.name).toBe("notes.txt");
    expect(out.type).toBe("text/plain");
    expect(Array.from(out.bytes)).toEqual(Array.from(content));
  });

  it("round-trips packed file bytes through key-mode encryption", async () => {
    const packed = packFilePayload("kéy ✓.bin", "application/octet-stream", content);
    const { blob, key } = await encryptBytes(packed);
    const out = unpackFilePayload(await decryptBytes(blob, key));
    expect(out.name).toBe("kéy ✓.bin");
    expect(Array.from(out.bytes)).toEqual(Array.from(content));
  });

  it("round-trips packed file bytes through passphrase encryption", async () => {
    const packed = packFilePayload("a.pdf", "application/pdf", content);
    const blob = await encryptBytesWithPassphrase(packed, "open sesame");
    const out = unpackFilePayload(
      await decryptBytesWithPassphrase(blob, "open sesame"),
    );
    expect(out.name).toBe("a.pdf");
    expect(Array.from(out.bytes)).toEqual(Array.from(content));
    await expect(decryptBytesWithPassphrase(blob, "wrong")).rejects.toBeTruthy();
  });
});
