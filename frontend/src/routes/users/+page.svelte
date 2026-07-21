<script>
    import { base, users } from "$lib/api.js";
    import { toast } from "$lib/stores/toast.svelte.js";
    import { sessionState, loadSession } from "$lib/stores/session.svelte.js";
    import { t } from "$lib/i18n.svelte.js";

    let rows = $state([]);
    let ready = $state(false);

    // create form
    let cEmail = $state("");
    let cName = $state("");
    let cRole = $state("user");
    let cPassword = $state("");
    let cBusy = $state(false);

    $effect(() => {
        loadSession().then(() => {
            if (sessionState.authEnabled && !sessionState.isAdmin) {
                window.location.href = base + "/";
                return;
            }
            ready = true;
            refresh();
        });
    });

    async function refresh() {
        try {
            const r = await users.list();
            rows = r?.users ?? [];
        } catch (err) {
            toast.error(err.message);
        }
    }

    async function createUser(e) {
        e.preventDefault();
        cBusy = true;
        try {
            await users.create({
                email: cEmail.trim(),
                name: cName.trim(),
                role: cRole,
                password: cPassword || undefined,
            });
            toast.success(t(cPassword ? "users.localCreated" : "users.oidcCreated"));
            cEmail = cName = cPassword = "";
            cRole = "user";
            await refresh();
        } catch (err) {
            toast.error(err.message);
        } finally {
            cBusy = false;
        }
    }

    async function update(email, body, ok) {
        try {
            await users.update(email, body);
            if (ok) toast.success(ok);
            await refresh();
        } catch (err) {
            toast.error(err.message);
        }
    }

    function setRole(u, role) {
        if (role === u.role) return;
        update(u.email, { role }, t("users.roleSet", { email: u.email, role }));
    }

    function toggleEnabled(u) {
        update(u.email, { enabled: !u.enabled }, t(u.enabled ? "users.disabled" : "users.enabled"));
    }

    function resetPassword(u) {
        const pw = window.prompt(t("users.pwPrompt", { email: u.email }));
        if (!pw) return;
        update(u.email, { password: pw }, t("users.pwReset"));
    }

    function revoke2fa(u) {
        if (!window.confirm(t("users.confirm2fa", { email: u.email }))) return;
        update(u.email, { clear_totp: true }, t("users.twofaRevoked"));
    }

    function revokePasskeys(u) {
        if (!window.confirm(t("users.confirmKeys", { email: u.email }))) return;
        update(u.email, { clear_passkeys: true }, t("users.keysRemoved"));
    }

    async function del(u) {
        if (!window.confirm(t("users.confirmDelete", { email: u.email }))) return;
        try {
            await users.remove(u.email);
            toast.success(t("users.deleted"));
            await refresh();
        } catch (err) {
            toast.error(err.message);
        }
    }
</script>

<div class="container wide">
    {#if ready}
        <div class="card">
            <h2>{t("users.title")}</h2>
            <p class="muted">
                {t("users.intro")}
            </p>
            <form class="create" onsubmit={createUser}>
                <input class="input" type="email" bind:value={cEmail} placeholder={t("users.phEmail")} required />
                <input class="input" bind:value={cName} placeholder={t("users.phName")} />
                <select class="input" bind:value={cRole}>
                    <option value="user">{t("users.roleUser")}</option>
                    <option value="admin">{t("users.roleAdmin")}</option>
                </select>
                <input class="input" type="password" bind:value={cPassword} placeholder={t("users.phPassword")} />
                <button class="btn primary" type="submit" disabled={cBusy || !cEmail}>{t("users.add")}</button>
            </form>
        </div>

        <div class="card">
            <table class="tbl">
                <thead>
                    <tr>
                        <th>{t("users.colEmail")}</th>
                        <th>{t("users.colRole")}</th>
                        <th>{t("users.colSource")}</th>
                        <th>{t("users.col2fa")}</th>
                        <th>{t("users.colPasskeys")}</th>
                        <th>{t("users.colEnabled")}</th>
                        <th>{t("users.colActions")}</th>
                    </tr>
                </thead>
                <tbody>
                    {#each rows as u (u.email)}
                        <tr class:disabled={!u.enabled}>
                            <td>{u.email}{#if u.pinned}<span class="tag">{t("users.pinned")}</span>{/if}</td>
                            <td>
                                <select
                                    class="input sm"
                                    value={u.role}
                                    onchange={(e) => setRole(u, e.currentTarget.value)}
                                >
                                    <option value="user">{t("users.roleUser")}</option>
                                    <option value="admin">{t("users.roleAdmin")}</option>
                                </select>
                            </td>
                            <td class="mono">{u.source}</td>
                            <td>{u.totp_enabled ? t("users.on") : "-"}</td>
                            <td>{u.passkey_count || 0}</td>
                            <td>
                                <button class="btn xs" onclick={() => toggleEnabled(u)}>
                                    {u.enabled ? t("users.disable") : t("users.enable")}
                                </button>
                            </td>
                            <td class="actions">
                                {#if u.has_password}
                                    <button class="btn xs" onclick={() => resetPassword(u)}>{t("users.resetPw")}</button>
                                {/if}
                                {#if u.totp_enabled}
                                    <button class="btn xs" onclick={() => revoke2fa(u)}>{t("users.revoke2fa")}</button>
                                {/if}
                                {#if u.passkey_count > 0}
                                    <button class="btn xs" onclick={() => revokePasskeys(u)}>{t("users.revokeKeys")}</button>
                                {/if}
                                <button class="btn xs danger" onclick={() => del(u)}>{t("users.delete")}</button>
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {/if}
</div>

<style>
    .container.wide {
        max-width: 920px;
    }
    .create {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        align-items: center;
    }
    .create .input {
        flex: 1;
        min-width: 120px;
    }
    .tbl {
        width: 100%;
        border-collapse: collapse;
    }
    .tbl th,
    .tbl td {
        text-align: left;
        padding: 6px 8px;
        border-bottom: 1px solid var(--line-2);
        font-size: var(--fs-small, 14px);
        vertical-align: middle;
    }
    tr.disabled {
        opacity: 0.5;
    }
    .input.sm {
        padding: 2px 6px;
        width: auto;
    }
    .btn.xs {
        padding: 2px 8px;
        font-size: var(--fs-micro, 12px);
    }
    .btn.danger {
        border-color: var(--crit, #ef4444);
        color: var(--crit, #ef4444);
    }
    .actions {
        display: flex;
        gap: 6px;
        flex-wrap: wrap;
    }
    .tag {
        margin-left: 6px;
        font-size: var(--fs-micro, 12px);
        color: var(--fg-3);
        border: 1px solid var(--line-2);
        border-radius: var(--r-pill, 999px);
        padding: 0 6px;
    }
</style>
