// Theme selection: "system" | "light" | "dark", persisted in localStorage.
// The *effective* theme (light|dark) is written to <html data-theme>; app.html
// applies it pre-paint to avoid a flash, and this store keeps it in sync after
// hydration and when the OS theme flips while we're following "system".
const STORAGE_KEY = "share-theme";
const CHOICES = ["system", "light", "dark"];

function readChoice() {
  if (typeof localStorage === "undefined") return "system";
  const v = localStorage.getItem(STORAGE_KEY);
  return CHOICES.includes(v) ? v : "system";
}

const state = $state({ choice: readChoice() });

function systemPrefersDark() {
  return (
    typeof matchMedia !== "undefined" &&
    matchMedia("(prefers-color-scheme: dark)").matches
  );
}

function effective(choice) {
  if (choice === "system") return systemPrefersDark() ? "dark" : "light";
  return choice;
}

function apply() {
  if (typeof document !== "undefined") {
    document.documentElement.dataset.theme = effective(state.choice);
  }
}

let mediaBound = false;

// initTheme reconciles the store with the pre-paint value and starts following
// the OS theme. Call once after mount (browser only).
export function initTheme() {
  if (!mediaBound && typeof matchMedia !== "undefined") {
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (state.choice === "system") apply();
    });
    mediaBound = true;
  }
  apply();
}

export function setTheme(choice) {
  if (!CHOICES.includes(choice)) return;
  state.choice = choice;
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(STORAGE_KEY, choice);
  }
  apply();
}

// cycleTheme steps system → light → dark → system, for a single toggle button.
export function cycleTheme() {
  const i = CHOICES.indexOf(state.choice);
  setTheme(CHOICES[(i + 1) % CHOICES.length]);
}

export const themeState = {
  get choice() {
    return state.choice;
  },
  get effective() {
    return effective(state.choice);
  },
};
