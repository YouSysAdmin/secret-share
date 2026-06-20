import { describe, it, expect } from "vitest";
import { encryptToPayload, decryptFromPayload } from "./crypto.js";

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
