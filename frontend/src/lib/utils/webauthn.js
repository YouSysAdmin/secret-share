// Minimal WebAuthn (passkey) browser glue. The server (go-webauthn) uses the
// standard WebAuthn JSON where binary fields are base64url strings, but the
// browser APIs want/produce ArrayBuffers. These helpers convert between the two
// so the rest of the app deals only in plain JSON.

function b64uToBuf(s) {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = t.length % 4 ? "=".repeat(4 - (t.length % 4)) : "";
  const bin = atob(t + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// supported reports whether this browser can do WebAuthn at all.
export function supported() {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}

// createCredential runs the registration ceremony. opts is the server's
// CredentialCreation ({publicKey:{...}}). Returns the attestation as JSON.
export async function createCredential(opts) {
  const pk = structuredClone(opts.publicKey);
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  if (Array.isArray(pk.excludeCredentials)) {
    pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  }
  const cred = await navigator.credentials.create({ publicKey: pk });
  if (!cred) throw new Error("passkey registration was canceled");
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports?.() ?? undefined,
    },
  };
}

// getCredential runs the assertion (login) ceremony. opts is the server's
// CredentialAssertion ({publicKey:{...}}). Returns the assertion as JSON.
export async function getCredential(opts) {
  const pk = structuredClone(opts.publicKey);
  pk.challenge = b64uToBuf(pk.challenge);
  if (Array.isArray(pk.allowCredentials)) {
    pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  }
  const cred = await navigator.credentials.get({ publicKey: pk });
  if (!cred) throw new Error("passkey sign-in was canceled");
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : undefined,
    },
  };
}
