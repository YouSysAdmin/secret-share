<script>
  import {account, passkey, signinRedirect, twofa} from "$lib/api.js";
  import {toast} from "$lib/stores/toast.svelte.js";
  import * as webauthn from "$lib/utils/webauthn.js";
  import {loadSession, refreshSession, sessionState,} from "$lib/stores/session.svelte.js";
  import {t} from "$lib/i18n.svelte.js";

  const passkeySupported = webauthn.supported();

  // change password
  let curPw = $state("");
  let newPw = $state("");

  // change email
  let newEmail = $state("");
  let emailPw = $state("");

  // 2fa
  let twofaPw = $state("");
  let setup = $state(null); // { secret, otpauth_url, qr_png_base64 }
  let confirmCode = $state("");
  let recoveryCodes = $state(null);

  // passkeys
  let passkeys = $state([]);
  let pkName = $state("");
  let pkPw = $state("");
  let pkBusy = $state(false);

  let ready = $state(false);

  // Local-credential self-service (password, email, 2FA, passkeys) only applies
  // to accounts that have a local password. OIDC users manage all of that at
  // their identity provider, so those sections are hidden for them.
  const isLocal = $derived(!!sessionState.user?.has_password);

  $effect(() => {
    loadSession().then(() => {
      if (sessionState.authEnabled && !sessionState.user) {
        signinRedirect();
        return;
      }
      ready = true;
      refreshPasskeys();
    });
  });

  async function refreshPasskeys() {
    try {
      const r = await passkey.list();
      passkeys = r?.passkeys ?? [];
    } catch {
      /* not a local account / not allowed */
    }
  }

  async function doChangePassword(e) {
    e.preventDefault();
    try {
      await account.changePassword(curPw, newPw);
      curPw = newPw = "";
      toast.success(t("account.pwChanged"));
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function doChangeEmail(e) {
    e.preventDefault();
    try {
      const r = await account.changeEmail(newEmail, emailPw);
      emailPw = "";
      newEmail = "";
      toast.success(t("account.emailChanged", {email: r.email}));
      await refreshSession();
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function startTwoFA(e) {
    e.preventDefault();
    try {
      setup = await twofa.setup(twofaPw);
      twofaPw = "";
      confirmCode = "";
      recoveryCodes = null;
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function confirmTwoFA(e) {
    e.preventDefault();
    try {
      const r = await twofa.confirm(confirmCode.trim());
      recoveryCodes = r.recovery_codes || [];
      setup = null;
      await refreshSession();
      toast.success(t("account.twofaEnabled"));
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function disableTwoFA(e) {
    e.preventDefault();
    try {
      await twofa.disable(twofaPw);
      twofaPw = "";
      recoveryCodes = null;
      await refreshSession();
      toast.success(t("account.twofaDisabled"));
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function regenCodes(e) {
    e.preventDefault();
    try {
      const r = await twofa.regenerateRecoveryCodes(twofaPw);
      twofaPw = "";
      recoveryCodes = r.recovery_codes || [];
      toast.success(t("account.newCodes"));
    } catch (err) {
      toast.error(err.message);
    }
  }

  async function addPasskey(e) {
    e.preventDefault();
    pkBusy = true;
    try {
      const opts = await passkey.registerBegin(pkPw);
      const cred = await webauthn.createCredential(opts);
      await passkey.registerFinish(cred, pkName.trim() || "passkey");
      pkPw = "";
      pkName = "";
      toast.success(t("account.pkAdded"));
      await refreshPasskeys();
    } catch (err) {
      if (err?.name !== "NotAllowedError") toast.error(err.message);
    } finally {
      pkBusy = false;
    }
  }

  async function removePasskey(id) {
    const pw = window.prompt(t("account.pkRemovePrompt"));
    if (!pw) return;
    try {
      await passkey.remove(id, pw);
      toast.success(t("account.pkRemoved"));
      await refreshPasskeys();
    } catch (err) {
      toast.error(err.message);
    }
  }

  function fmtWhen(s) {
    if (!s) return "";
    const d = new Date(s);
    return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
  }

  async function copyCodes() {
    try {
      await navigator.clipboard.writeText((recoveryCodes || []).join("\n"));
      toast.success(t("account.codesCopied"));
    } catch {
      toast.error(t("common.copyFailed"));
    }
  }
</script>

<div class="container">
  {#if ready}
    <div class="card">
      <h2>{t("account.title")}</h2>
      <p class="muted">
        {t("account.signedInAs")} <code>{sessionState.user?.email}</code>
        ({sessionState.user?.role}).
      </p>
    </div>

    {#if isLocal}
      <div class="card">
        <h3>{t("account.changePassword")}</h3>
        <form onsubmit={doChangePassword}>
          <div class="field">
            <label for="cur">{t("account.currentPassword")}</label>
            <input id="cur" class="input" type="password" bind:value={curPw}/>
          </div>
          <div class="field">
            <label for="new">{t("account.newPassword")}</label>
            <input id="new" class="input" type="password" bind:value={newPw}/>
          </div>
          <button class="btn primary" type="submit" disabled={!curPw || !newPw}>
            {t("account.updatePassword")}
          </button>
        </form>
      </div>

      <div class="card">
        <h3>{t("account.changeEmail")}</h3>
        <form onsubmit={doChangeEmail}>
          <div class="field">
            <label for="ne">{t("account.newEmail")}</label>
            <input id="ne" class="input" type="email" bind:value={newEmail}/>
          </div>
          <div class="field">
            <label for="ep">{t("account.currentPassword")}</label>
            <input id="ep" class="input" type="password" bind:value={emailPw}/>
          </div>
          <button class="btn primary" type="submit" disabled={!newEmail || !emailPw}>
            {t("account.updateEmail")}
          </button>
        </form>
      </div>

      <div class="card">
        <h3>{t("account.twofa")}</h3>
        {#if recoveryCodes}
          <div class="banner ok">
            {t("account.recoverySave")}
          </div>
          <pre class="codes mono">{recoveryCodes.join("\n")}</pre>
          <button class="btn" onclick={copyCodes}>{t("account.copyCodes")}</button>
        {:else if setup}
          <p class="muted">
            {t("account.scanQR")}
          </p>
          <img
            class="qr"
            src={"data:image/png;base64," + setup.qr_png_base64}
            alt={t("account.totpQRAlt")}
            width="200"
            height="200"
          />
          <div class="field">
            <span class="muted">{t("account.secretManual")}</span>
            <code class="mono">{setup.secret}</code>
          </div>
          <form onsubmit={confirmTwoFA}>
            <div class="field">
              <label for="cc">{t("account.code")}</label>
              <input
                id="cc"
                class="input mono"
                inputmode="numeric"
                autocomplete="one-time-code"
                bind:value={confirmCode}
                placeholder="123456"
              />
            </div>
            <button class="btn primary" type="submit" disabled={!confirmCode.trim()}>
              {t("account.enable2fa")}
            </button>
          </form>
        {:else if sessionState.user?.totp_enabled}
          <div class="banner ok">
            {t("account.protected")}
          </div>
          <form onsubmit={disableTwoFA}>
            <div class="field">
              <label for="tp">{t("account.confirmPassword")}</label>
              <input id="tp" class="input" type="password" bind:value={twofaPw}/>
            </div>
            <div class="row">
              <button class="btn" onclick={regenCodes} disabled={!twofaPw}>
                {t("account.regenCodes")}
              </button>
              <button class="btn danger" type="submit" disabled={!twofaPw}>
                {t("account.disable2fa")}
              </button>
            </div>
          </form>
        {:else}
          <p class="muted">
            {t("account.addFactor")}
          </p>
          <form onsubmit={startTwoFA}>
            <div class="field">
              <label for="t2p">{t("account.confirmPassword")}</label>
              <input id="t2p" class="input" type="password" bind:value={twofaPw}/>
            </div>
            <button class="btn primary" type="submit" disabled={!twofaPw}>
              {t("account.setup2fa")}
            </button>
          </form>
        {/if}
      </div>

      {#if passkeySupported}
        <div class="card">
          <h3>{t("account.passkeys")}</h3>
          {#if passkeys.length === 0}
            <p class="muted">{t("account.noPasskeys")}</p>
          {:else}
            <table class="tbl">
              <thead>
              <tr>
                <th>{t("account.colName")}</th>
                <th>{t("account.colAdded")}</th>
                <th></th>
              </tr>
              </thead>
              <tbody>
              {#each passkeys as pk (pk.id)}
                <tr>
                  <td>{pk.name}</td>
                  <td class="mono">{fmtWhen(pk.added_at)}</td>
                  <td>
                    <button
                      class="btn danger"
                      onclick={() => removePasskey(pk.id)}
                    >
                      {t("account.remove")}
                    </button>
                  </td>
                </tr>
              {/each}
              </tbody>
            </table>
          {/if}
          <form onsubmit={addPasskey} style="margin-top:12px">
            <div class="field">
              <label for="pkn">{t("account.pkNameLabel")}</label>
              <input id="pkn" class="input" bind:value={pkName} placeholder={t("account.pkNamePlaceholder")}/>
            </div>
            <div class="field">
              <label for="pkp">{t("account.confirmPassword")}</label>
              <input id="pkp" class="input" type="password" bind:value={pkPw}/>
            </div>
            <button class="btn primary" type="submit" disabled={pkBusy || !pkPw}>
              {pkBusy ? t("account.pkBusy") : t("account.addPasskey")}
            </button>
          </form>
        </div>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .banner.ok {
    background: var(--ok-bg, rgba(74, 222, 128, 0.12));
    border: 1px solid var(--ok, #4ade80);
    color: var(--fg-0);
    border-radius: var(--r-sm, 5px);
    padding: 8px 12px;
    margin-bottom: 12px;
    font-size: var(--fs-small, 14px);
  }

  .qr {
    border-radius: var(--r-sm, 5px);
    background: #fff;
    padding: 6px;
    display: block;
    margin-bottom: 10px;
  }

  .codes {
    background: var(--bg-1);
    border: 1px solid var(--line-2);
    border-radius: var(--r-sm, 5px);
    padding: 12px;
    margin: 8px 0;
    white-space: pre;
    overflow-x: auto;
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
  }

  .btn.danger {
    border-color: var(--crit, #ef4444);
    color: var(--crit, #ef4444);
  }

  .row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
</style>
