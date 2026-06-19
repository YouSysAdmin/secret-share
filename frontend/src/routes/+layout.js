// Static routes prerender, the dynamic /s/[id] route opts out (see its +page.js)
// and is served via the index.html fallback.
export const prerender = true;
export const ssr = false;
