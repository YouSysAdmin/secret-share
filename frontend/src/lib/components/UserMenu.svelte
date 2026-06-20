<script>
    import { base, auth } from "$lib/api.js";
    import { sessionState, refreshSession } from "$lib/stores/session.svelte.js";

    let open = $state(false);
    let root;

    function close() {
        open = false;
    }

    async function logout() {
        close();
        try {
            await auth.logout();
        } catch {
            /* idempotent */
        }
        await refreshSession();
        window.location.href = base + "/signin";
    }

    // Close the dropdown on outside click / Escape. Only bound while open.
    $effect(() => {
        if (!open) return;
        function onPointer(e) {
            if (root && !root.contains(e.target)) close();
        }
        function onKey(e) {
            if (e.key === "Escape") close();
        }
        document.addEventListener("click", onPointer);
        document.addEventListener("keydown", onKey);
        return () => {
            document.removeEventListener("click", onPointer);
            document.removeEventListener("keydown", onKey);
        };
    });
</script>

<div class="user-menu" bind:this={root}>
    <button
        type="button"
        class="trigger"
        onclick={() => (open = !open)}
        aria-haspopup="menu"
        aria-expanded={open}
        title={sessionState.user.email}
    >
        <svg
            class="avatar"
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            <circle cx="12" cy="8" r="4" />
            <path d="M4 21a8 8 0 0 1 16 0" />
        </svg>
        <span class="email">{sessionState.user.email}</span>
        <svg
            class="chev"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            <path d="M6 9l6 6 6-6" />
        </svg>
    </button>

    {#if open}
        <div class="menu" role="menu">
            <div class="menu-email" title={sessionState.user.email}>
                {sessionState.user.email}
            </div>
            {#if sessionState.isAdmin}
                <a
                    class="menu-item"
                    role="menuitem"
                    href="{base}/users"
                    onclick={close}>Users</a
                >
            {/if}
            <a
                class="menu-item"
                role="menuitem"
                href="{base}/account"
                onclick={close}>Account</a
            >
            <button class="menu-item danger" role="menuitem" onclick={logout}>
                Sign out
            </button>
        </div>
    {/if}
</div>

<style>
    .user-menu {
        position: relative;
        display: flex;
        align-items: center;
    }

    .trigger {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        height: 32px;
        padding: 0 8px 0 10px;
        background: none;
        border: 1px solid var(--line-2);
        border-radius: var(--r-sm);
        color: var(--fg-1);
        font: inherit;
        font-size: var(--fs-small, 14px);
        cursor: pointer;
        transition: all var(--dur-fast);
    }
    .trigger:hover {
        color: var(--fg-0);
        border-color: var(--line-3);
        background: var(--bg-3);
    }
    .avatar {
        flex: none;
        color: var(--fg-2);
    }
    .email {
        max-width: 180px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .chev {
        flex: none;
        color: var(--fg-3);
        transition: transform var(--dur-fast);
    }
    .trigger[aria-expanded="true"] .chev {
        transform: rotate(180deg);
    }

    .menu {
        position: absolute;
        top: calc(100% + 8px);
        right: 0;
        min-width: 200px;
        padding: 6px;
        background: var(--bg-2);
        border: 1px solid var(--line-2);
        border-radius: var(--r-md);
        box-shadow: var(--shadow-lg);
        z-index: 1000;
    }
    .menu-email {
        padding: 8px 10px;
        margin-bottom: 4px;
        border-bottom: 1px solid var(--line-1);
        font-family: var(--font-mono);
        font-size: 12px;
        color: var(--fg-3);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .menu-item {
        display: block;
        width: 100%;
        padding: 9px 10px;
        background: none;
        border: none;
        border-radius: var(--r-sm);
        color: var(--fg-1);
        font: inherit;
        font-size: 14px;
        text-align: left;
        text-decoration: none;
        cursor: pointer;
    }
    .menu-item:hover {
        background: var(--bg-3);
        color: var(--fg-0);
    }
    .menu-item.danger {
        color: var(--brand-400);
    }

    /* On narrow screens drop the email text — icon + chevron only. */
    @media (max-width: 560px) {
        .email {
            display: none;
        }
        .trigger {
            padding: 0 6px;
        }
    }
</style>
