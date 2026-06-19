<script>
    import "../app.css";
    import { base } from "$lib/api.js";
    import Toaster from "$lib/components/Toaster.svelte";

    let { children } = $props();
</script>

<nav class="app-nav">
    <a class="brand" href="{base}/">
        <svg
            class="brand-logo"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        Share
    </a>
</nav>

{@render children()}

<Toaster />
