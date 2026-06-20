<script>
    import "../app.css";
    import { base, auth } from "$lib/api.js";
    import Toaster from "$lib/components/Toaster.svelte";
    import ThemeToggle from "$lib/components/ThemeToggle.svelte";
    import {
        sessionState,
        loadSession,
        refreshSession,
    } from "$lib/stores/session.svelte.js";
    import { initTheme } from "$lib/stores/theme.svelte.js";

    let { children } = $props();

    $effect(() => {
        loadSession();
        initTheme();
    });

    async function logout() {
        try {
            await auth.logout();
        } catch {
            /* idempotent */
        }
        await refreshSession();
        window.location.href = base + "/signin";
    }
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
                {#if sessionState.isAdmin}
                    <a class="nav-link" href="{base}/users">Users</a>
                {/if}
                <a class="nav-link" href="{base}/account">{sessionState.user.email}</a>
                <button class="btn primary" onclick={logout}>Sign out</button>
            {:else if sessionState.loaded}
                <a class="btn primary" href="{base}/signin">Sign in</a>
            {/if}
        {/if}
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
    .nav-link {
        color: var(--fg-2);
        text-decoration: none;
        font-size: var(--fs-small, 14px);
    }
    .nav-link:hover {
        color: var(--fg-0);
    }
    .as-btn {
        background: none;
        border: none;
        cursor: pointer;
        padding: 0;
    }
    .nav-email {
        color: var(--fg-3);
        font-size: var(--fs-small, 14px);
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
</style>
