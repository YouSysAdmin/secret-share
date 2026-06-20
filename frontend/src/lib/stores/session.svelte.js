import { auth } from "$lib/api.js";

// Shared client-side session state. loadSession() probes /auth/me once; the SPA
// reads sessionState to decide what to render.
const state = $state({
  loaded: false,
  authEnabled: false,
  user: null, // { sub, email, name, role, totp_enabled } | null
});

let inflight = null;

export function loadSession() {
  if (!inflight) {
    inflight = auth
      .me()
      .then((r) => {
        if (r) {
          state.authEnabled = !!r.auth_enabled;
          state.user = r.user || null;
        }
        state.loaded = true;
        return state;
      })
      .catch(() => {
        state.loaded = true;
        return state;
      });
  }
  return inflight;
}

// refreshSession forces a re-probe (after login/logout/email change).
export function refreshSession() {
  inflight = null;
  return loadSession();
}

export const sessionState = {
  get loaded() {
    return state.loaded;
  },
  get authEnabled() {
    return state.authEnabled;
  },
  get user() {
    return state.user;
  },
  // In public mode everyone has full access; otherwise admin is role-gated.
  get isAdmin() {
    return !state.authEnabled || state.user?.role === "admin";
  },
};
