<script>
    import { themeState, cycleTheme } from "$lib/stores/theme.svelte.js";
    import { t } from "$lib/i18n.svelte.js";
</script>

<button
    type="button"
    class="theme-toggle"
    onclick={cycleTheme}
    title={t("theme.title", { name: t(`theme.${themeState.choice}`) })}
    aria-label={t("theme.title", { name: t(`theme.${themeState.choice}`) })}
>
    {#if themeState.choice === "system"}
        <!-- monitor -->
        <svg
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
            <rect x="2" y="3" width="20" height="14" rx="2" />
            <path d="M8 21h8M12 17v4" />
        </svg>
    {:else if themeState.choice === "light"}
        <!-- sun -->
        <svg
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
            <circle cx="12" cy="12" r="4" />
            <path
                d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"
            />
        </svg>
    {:else}
        <!-- moon -->
        <svg
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
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
    {/if}
</button>

<style>
    .theme-toggle {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        padding: 0;
        background: none;
        border: 1px solid var(--line-2);
        border-radius: var(--r-sm);
        color: var(--fg-2);
        cursor: pointer;
        transition: all var(--dur-fast);
    }
    .theme-toggle:hover {
        color: var(--fg-0);
        border-color: var(--line-3);
        background: var(--bg-3);
    }
</style>
