import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

// During `vite dev` the SPA's API calls hit /api/* - proxy those to the Go
// server so the browser talks to it without CORS. Override the target with
// SHARE_SERVER=https://host:port bun run dev when needed.
const target = process.env.SHARE_SERVER || "http://localhost:8080";

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target, changeOrigin: true, secure: false },
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.{test,spec}.{js,ts}"],
  },
});
