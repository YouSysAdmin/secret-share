<script>
    import { base, users } from "$lib/api.js";
    import { toast } from "$lib/stores/toast.svelte.js";
    import { sessionState, loadSession } from "$lib/stores/session.svelte.js";

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
            toast.success(cPassword ? "Local user created." : "OIDC user created.");
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
        update(u.email, { role }, `${u.email} is now ${role}.`);
    }

    function toggleEnabled(u) {
        update(u.email, { enabled: !u.enabled }, u.enabled ? "User disabled." : "User enabled.");
    }

    function resetPassword(u) {
        const pw = window.prompt(`New password for ${u.email} (8-72 chars):`);
        if (!pw) return;
        update(u.email, { password: pw }, "Password reset.");
    }

    function revoke2fa(u) {
        if (!window.confirm(`Revoke 2FA for ${u.email}?`)) return;
        update(u.email, { clear_totp: true }, "2FA revoked.");
    }

    function revokePasskeys(u) {
        if (!window.confirm(`Remove all passkeys for ${u.email}?`)) return;
        update(u.email, { clear_passkeys: true }, "Passkeys removed.");
    }

    async function del(u) {
        if (!window.confirm(`Delete ${u.email}? This cannot be undone.`)) return;
        try {
            await users.remove(u.email);
            toast.success("User deleted.");
            await refresh();
        } catch (err) {
            toast.error(err.message);
        }
    }
</script>

<div class="container wide">
    {#if ready}
        <div class="card">
            <h2>Users</h2>
            <p class="muted">
                Manage who can sign in. A password makes a local account; leave it
                blank for an SSO account provisioned by email.
            </p>
            <form class="create" onsubmit={createUser}>
                <input class="input" type="email" bind:value={cEmail} placeholder="email" required />
                <input class="input" bind:value={cName} placeholder="name (optional)" />
                <select class="input" bind:value={cRole}>
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                </select>
                <input class="input" type="password" bind:value={cPassword} placeholder="password (optional)" />
                <button class="btn primary" type="submit" disabled={cBusy || !cEmail}>Add</button>
            </form>
        </div>

        <div class="card">
            <table class="tbl">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Source</th>
                        <th>2FA</th>
                        <th>Passkeys</th>
                        <th>Enabled</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {#each rows as u (u.email)}
                        <tr class:disabled={!u.enabled}>
                            <td>{u.email}{#if u.pinned}<span class="tag">pinned</span>{/if}</td>
                            <td>
                                <select
                                    class="input sm"
                                    value={u.role}
                                    onchange={(e) => setRole(u, e.currentTarget.value)}
                                >
                                    <option value="user">user</option>
                                    <option value="admin">admin</option>
                                </select>
                            </td>
                            <td class="mono">{u.source}</td>
                            <td>{u.totp_enabled ? "on" : "-"}</td>
                            <td>{u.passkey_count || 0}</td>
                            <td>
                                <button class="btn xs" onclick={() => toggleEnabled(u)}>
                                    {u.enabled ? "disable" : "enable"}
                                </button>
                            </td>
                            <td class="actions">
                                {#if u.has_password}
                                    <button class="btn xs" onclick={() => resetPassword(u)}>reset pw</button>
                                {/if}
                                {#if u.totp_enabled}
                                    <button class="btn xs" onclick={() => revoke2fa(u)}>revoke 2FA</button>
                                {/if}
                                {#if u.passkey_count > 0}
                                    <button class="btn xs" onclick={() => revokePasskeys(u)}>revoke keys</button>
                                {/if}
                                <button class="btn xs danger" onclick={() => del(u)}>delete</button>
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
