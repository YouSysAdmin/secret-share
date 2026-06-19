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

async function call(path, opts = {}) {
  const res = await fetch(base + path, {
    credentials: "same-origin",
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
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
