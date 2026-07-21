<script>
    import { base, auth, passkey, takeReturnTo } from "$lib/api.js";
    import * as webauthn from "$lib/utils/webauthn.js";
    import { t } from "$lib/i18n.svelte.js";

    let info = $state(null); // { auth_enabled, password_enabled, passkey_enabled, oidc_providers, gate }
    let email = $state("");
    let password = $state("");
    let code = $state("");
    let mfaStep = $state(false);
    let pwBusy = $state(false);
    let pkBusy = $state(false);
    let error = $state(null);

    const ssoErrorKeys = {
        sso_idp_error: "signin.ssoIdpError",
        sso_bad_callback: "signin.ssoBadCallback",
        sso_state_missing: "signin.ssoStateMissing",
        sso_token_invalid: "signin.ssoTokenInvalid",
        sso_access_denied: "signin.ssoAccessDenied",
        sso_internal: "signin.ssoInternal",
    };

    const passkeySupported = webauthn.supported();

    // goNext sends the user to where they came from (the stash, incl. a secret
    // link's #key) or the app root. One-shot: the stash is single-consume, and
    // both the "already signed in" mount check and the login handlers can fire, so
    // the guard makes sure only the FIRST caller navigates - otherwise a late
    // auth.me() (resolving after a fresh login) would re-read the now-empty stash
    // and bounce to "/", which is exactly the OIDC-lands-on-the-form bug.
    let redirecting = false;
    function goNext() {
        if (redirecting) return;
        redirecting = true;
        window.location.href = takeReturnTo();
    }

    $effect(() => {
        const err = new URLSearchParams(window.location.search).get("err");
        if (err) error = t(ssoErrorKeys[err] || "signin.failed");
        // Already signed in (incl. the OIDC return, which redirects here)? Go where
        // they were headed.
        auth.me().then((r) => {
            if (r?.user) goNext();
        });
        auth.info().then((r) => {
            info = r;
            // No auth configured at all -> nothing to sign into; send home.
            if (r && !r.auth_enabled && !redirecting) window.location.href = base + "/";
        });
    });

    function startOIDC(id) {
        window.location.href = `${base}/api/auth/oidc/${encodeURIComponent(id)}/start`;
    }

    async function startPasskey() {
        error = null;
        pkBusy = true;
        try {
            const opts = await passkey.loginBegin();
            const assertion = await webauthn.getCredential(opts);
            await passkey.loginFinish(assertion);
            goNext();
        } catch (err) {
            if (err?.name !== "NotAllowedError") error = err.message;
        } finally {
            pkBusy = false;
        }
    }

    async function submitPassword(e) {
        e.preventDefault();
        error = null;
        pwBusy = true;
        try {
            const r = await auth.login(email, password, mfaStep ? code : undefined);
            if (r && r.mfa_required) {
                mfaStep = true;
                return;
            }
            goNext();
        } catch (err) {
            error = err.message || t("signin.invalidCreds");
        } finally {
            pwBusy = false;
        }
    }
</script>

<div class="container">
    <div class="card signin">
        <h2>{t("signin.title")}</h2>

        {#if error}
            <div class="banner err">{error}</div>
        {/if}

        {#if info}
            {#each info.oidc_providers ?? [] as p (p.id)}
                <button
                    class="btn primary block"
                    type="button"
                    onclick={() => startOIDC(p.id)}
                >
                    {t("signin.ssoWith", { label: p.label })}
                </button>
            {/each}

            {#if (info.oidc_providers?.length ?? 0) > 0 && (info.password_enabled || info.passkey_enabled)}
                <div class="divider"><span>{t("signin.or")}</span></div>
            {/if}

            {#if info.passkey_enabled && passkeySupported && !mfaStep}
                <button
                    class="btn block"
                    type="button"
                    onclick={startPasskey}
                    disabled={pkBusy}
                >
                    {pkBusy ? t("signin.passkeyBusy") : t("signin.passkey")}
                </button>
            {/if}

            {#if info.password_enabled}
                <form onsubmit={submitPassword}>
                    {#if !mfaStep}
                        <div class="field">
                            <label for="email">{t("signin.email")}</label>
                            <input
                                id="email"
                                class="input"
                                type="email"
                                autocomplete="username"
                                bind:value={email}
                                placeholder="you@example.com"
                            />
                        </div>
                        <div class="field">
                            <label for="password">{t("signin.password")}</label>
                            <input
                                id="password"
                                class="input"
                                type="password"
                                autocomplete="current-password"
                                bind:value={password}
                                placeholder="••••••••"
                            />
                        </div>
                        <button
                            class="btn primary block"
                            type="submit"
                            disabled={pwBusy || !email || !password}
                        >
                            {pwBusy ? t("signin.submitBusy") : t("signin.submit")}
                        </button>
                    {:else}
                        <p class="muted">
                            {t("signin.mfaHint")}
                        </p>
                        <div class="field">
                            <label for="code">{t("signin.codeLabel")}</label>
                            <input
                                id="code"
                                class="input mono"
                                type="text"
                                inputmode="numeric"
                                autocomplete="one-time-code"
                                bind:value={code}
                                placeholder="123456"
                            />
                        </div>
                        <button
                            class="btn primary block"
                            type="submit"
                            disabled={pwBusy || !code}
                        >
                            {pwBusy ? t("signin.verifying") : t("signin.verify")}
                        </button>
                    {/if}
                </form>
            {/if}

            {#if !info.password_enabled && !info.passkey_enabled && (info.oidc_providers?.length ?? 0) === 0}
                <p class="muted">{t("signin.noMethods")}</p>
            {/if}
        {/if}
    </div>
</div>

<style>
    .signin {
        max-width: 380px;
        margin: 8vh auto 0;
    }
    .banner.err {
        background: var(--crit-bg, rgba(239, 68, 68, 0.12));
        border: 1px solid var(--crit, #ef4444);
        color: var(--fg-0);
        border-radius: var(--r-sm, 5px);
        padding: 8px 12px;
        margin-bottom: 12px;
        font-size: var(--fs-small, 14px);
    }
    .divider {
        display: flex;
        align-items: center;
        text-align: center;
        color: var(--fg-3);
        font-size: var(--fs-small, 14px);
        margin: 14px 0;
    }
    .divider::before,
    .divider::after {
        content: "";
        flex: 1;
        border-bottom: 1px solid var(--line-2);
    }
    .divider span {
        padding: 0 10px;
    }
    .btn.block {
        width: 100%;
        margin-top: 8px;
    }
</style>
