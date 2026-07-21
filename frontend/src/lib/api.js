import { resolve } from "$app/paths";

export const base = resolve("/").slice(0, -1);

async function errorFromResponse(res) {
  let msg = `HTTP ${res.status}`;
  try {
    const j = JSON.parse(await res.text());
    if (j.error) msg = j.error;
  } catch {
    /* body not JSON */
  }
  const err = new Error(msg);
  err.status = res.status;
  return err;
}

const RETURN_KEY = "share_return_to";
// Stashes older than this are ignored, so an abandoned sign-in can't silently
// hijack a later, unrelated one.
const RETURN_TTL_MS = 10 * 60 * 1000;

// signinRedirect stashes where we are - path, query, AND the #fragment - then
// sends the browser to the sign-in page. localStorage (not sessionStorage) is
// used on purpose: the OIDC round-trip leaves and re-enters the origin and can
// land in a different tab context, and sessionStorage is tab-scoped, so it would
// be lost - localStorage survives. The fragment of a secret link holds the
// decryption key, so it must NEVER ride a query param to the server (that would
// break zero-knowledge); localStorage stays client-side.
export function signinRedirect() {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(
      RETURN_KEY,
      JSON.stringify({
        to: window.location.pathname + window.location.search + window.location.hash,
        at: Date.now(),
      }),
    );
  } catch {
    /* storage unavailable (private mode quota) - fall through to plain /signin */
  }
  window.location.href = `${base}/signin`;
}

// takeReturnTo returns the stashed post-login destination (clearing it), or the
// app root. Validated to be a same-origin path (no off-site redirect) and to be
// recent.
export function takeReturnTo() {
  let to = `${base}/`;
  try {
    const raw = localStorage.getItem(RETURN_KEY);
    localStorage.removeItem(RETURN_KEY);
    if (raw) {
      const v = JSON.parse(raw);
      if (
        v &&
        typeof v.to === "string" &&
        v.to.startsWith("/") &&
        !v.to.startsWith("//") &&
        Date.now() - (v.at || 0) < RETURN_TTL_MS
      ) {
        to = v.to;
      }
    }
  } catch {
    /* ignore */
  }
  return to;
}

// redirectOn401 bounces the browser to the sign-in page (remembering where we
// were) when a protected endpoint reports no session. The auth endpoints
// themselves are exempt so /auth/me can report "logged out" without looping.
function redirectOn401(res, path) {
  if (res.status !== 401) return false;
  if (path.startsWith("/api/auth/")) return false;
  if (typeof window === "undefined") return false;
  signinRedirect();
  return true;
}

async function call(path, opts = {}) {
  const res = await fetch(base + path, {
    credentials: "same-origin",
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (redirectOn401(res, path)) throw new Error("redirecting to sign-in");
  if (res.status === 204) return null;
  if (!res.ok) throw await errorFromResponse(res);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

export const config = () => call("/api/config");

export const secrets = {
  create: (body) =>
    call("/api/secrets", { method: "POST", body: JSON.stringify(body) }),
  meta: (id) => call(`/api/secrets/${encodeURIComponent(id)}/meta`),
  reveal: (id) =>
    call(`/api/secrets/${encodeURIComponent(id)}/reveal`, { method: "POST" }),
};

// Encrypted files. The create body is the raw opaque blob (not JSON), so the
// options ride headers; reveal returns raw bytes.
export const files = {
  create: async (blob, { ttl, private: priv } = {}) => {
    const headers = { "Content-Type": "application/octet-stream" };
    if (ttl) headers["X-Share-TTL"] = ttl;
    if (priv) headers["X-Share-Private"] = "true";
    const res = await fetch(base + "/api/files", {
      credentials: "same-origin",
      method: "POST",
      headers,
      body: blob,
    });
    if (redirectOn401(res, "/api/files")) throw new Error("redirecting to sign-in");
    if (!res.ok) throw await errorFromResponse(res);
    return JSON.parse(await res.text());
  },
  meta: (id) => call(`/api/files/${encodeURIComponent(id)}/meta`),
  reveal: async (id) => {
    const path = `/api/files/${encodeURIComponent(id)}/reveal`;
    const res = await fetch(base + path, {
      credentials: "same-origin",
      method: "POST",
    });
    if (redirectOn401(res, path)) throw new Error("redirecting to sign-in");
    if (!res.ok) throw await errorFromResponse(res);
    return new Uint8Array(await res.arrayBuffer());
  },
};

// --- private-mode (auth) endpoints ---

export const auth = {
  me: () => call("/api/auth/me"),
  info: () => call("/api/auth/info"),
  logout: () => call("/api/auth/logout", { method: "POST" }),
  // Returns {mfa_required:true} when the password was correct but 2FA is on.
  login: (email, password, code) =>
    call("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password, code: code || undefined }),
    }),
};

export const account = {
  changeEmail: (email, password) =>
    call("/api/account/email", { method: "POST", body: JSON.stringify({ email, password }) }),
  changePassword: (current_password, new_password) =>
    call("/api/account/password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),
};

export const twofa = {
  setup: (password) =>
    call("/api/account/2fa/setup", { method: "POST", body: JSON.stringify({ password }) }),
  confirm: (code) =>
    call("/api/account/2fa/confirm", { method: "POST", body: JSON.stringify({ code }) }),
  disable: (password) =>
    call("/api/account/2fa/disable", { method: "POST", body: JSON.stringify({ password }) }),
  regenerateRecoveryCodes: (password) =>
    call("/api/account/2fa/recovery-codes", { method: "POST", body: JSON.stringify({ password }) }),
};

export const passkey = {
  loginBegin: () => call("/api/auth/passkey/login/begin", { method: "POST" }),
  loginFinish: (cred) =>
    call("/api/auth/passkey/login/finish", { method: "POST", body: JSON.stringify(cred) }),
  registerBegin: (password) =>
    call("/api/account/passkeys/register/begin", { method: "POST", body: JSON.stringify({ password }) }),
  registerFinish: (cred, name) =>
    call(`/api/account/passkeys/register/finish?name=${encodeURIComponent(name || "passkey")}`, {
      method: "POST",
      body: JSON.stringify(cred),
    }),
  list: () => call("/api/account/passkeys"),
  remove: (id, password) =>
    call(`/api/account/passkeys/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({ password }),
    }),
};

export const users = {
  list: () => call("/api/users"),
  create: (body) => call("/api/users", { method: "POST", body: JSON.stringify(body) }),
  update: (email, body) =>
    call(`/api/users/${encodeURIComponent(email)}`, { method: "PUT", body: JSON.stringify(body) }),
  remove: (email) =>
    call(`/api/users/${encodeURIComponent(email)}`, { method: "DELETE" }),
};
