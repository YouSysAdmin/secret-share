let items = $state([]);
let seq = 0;

const DEFAULT_TTL = 4000;

function push(kind, message, ttl) {
  if (!message) return;
  const id = ++seq;
  items.push({ id, kind, message });
  if (ttl > 0 && typeof window !== "undefined") {
    setTimeout(() => dismiss(id), ttl);
  }
  return id;
}

export function dismiss(id) {
  const i = items.findIndex((t) => t.id === id);
  if (i !== -1) items.splice(i, 1);
}

export function toasts() {
  return items;
}

export const toast = {
  success: (m, ttl = DEFAULT_TTL) => push("ok", m, ttl),
  error: (m, ttl = 6000) => push("err", m, ttl),
  warn: (m, ttl = DEFAULT_TTL) => push("warn", m, ttl),
  info: (m, ttl = DEFAULT_TTL) => push("info", m, ttl),
};
