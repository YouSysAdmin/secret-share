import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

// adapter-static prerenders static routes to plain HTML at build time and emits
// a fallback (index.html) so the client router can serve dynamic routes like
// /s/[id]. Output lands in `dist/`, picked up by //go:embed all:frontend/dist in
// the module-root frontend.go.
//
// secret-share serves at the root (base ""), keeping share links short.
export default {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      pages: "dist",
      assets: "dist",
      fallback: "index.html",
      precompress: false,
      strict: false,
    }),
    paths: { base: "", relative: true },
  },
};
