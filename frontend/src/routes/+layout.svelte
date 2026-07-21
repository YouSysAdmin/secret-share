<script>
    import "../app.css";
    import { base } from "$lib/api.js";
    import Toaster from "$lib/components/Toaster.svelte";
    import ThemeToggle from "$lib/components/ThemeToggle.svelte";
    import LangSwitcher from "$lib/components/LangSwitcher.svelte";
    import UserMenu from "$lib/components/UserMenu.svelte";
    import { t } from "$lib/i18n.svelte.js";
    import { sessionState, loadSession } from "$lib/stores/session.svelte.js";
    import { initTheme } from "$lib/stores/theme.svelte.js";

    let { children } = $props();

    $effect(() => {
        loadSession();
        initTheme();
    });
</script>

<nav class="app-nav">
    <a class="brand" href="{base}/">
        <img
            class="brand-logo"
            src="{base}/logo.svg"
            width="16"
            height="16"
            alt=""
            aria-hidden="true"
        />
        Share
    </a>

    <div class="nav-right">
        {#if sessionState.authEnabled}
            {#if sessionState.user}
                <UserMenu />
            {:else if sessionState.loaded}
                <a class="btn primary" href="{base}/signin">{t("nav.signin")}</a>
            {/if}
        {/if}
        <LangSwitcher />
        <ThemeToggle />
    </div>
</nav>

{@render children()}

<Toaster />

<style>
    .app-nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .nav-right {
        display: flex;
        align-items: center;
        gap: 14px;
    }
</style>
