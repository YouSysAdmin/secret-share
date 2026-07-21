<script>
    import { i18n, setLocale, localeNames, t } from "$lib/i18n.svelte.js";
</script>

<select
    class="lang"
    value={i18n.locale}
    onchange={(e) => setLocale(e.currentTarget.value)}
    aria-label={t("lang.label")}
    title={t("lang.label")}
>
    {#each Object.entries(localeNames) as [code, name] (code)}
        <option value={code}>{name}</option>
    {/each}
</select>

<style>
    .lang {
        height: 32px;
        padding: 0 6px;
        background: none;
        border: 1px solid var(--line-2);
        border-radius: var(--r-sm);
        color: var(--fg-2);
        font: inherit;
        font-size: var(--fs-small, 14px);
        cursor: pointer;
        transition: all var(--dur-fast);
    }
    .lang:hover {
        color: var(--fg-0);
        border-color: var(--line-3);
        background: var(--bg-3);
    }
</style>
