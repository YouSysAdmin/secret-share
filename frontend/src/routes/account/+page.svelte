<script>
  import {account, passkey, signinRedirect, twofa} from "$lib/api.js";
  import {toast} from "$lib/stores/toast.svelte.js";
  import * as webauthn from "$lib/utils/webauthn.js";
  import {loadSession, refreshSession, sessionState,} from "$lib/stores/session.svelte.js";

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
      toast.success("Password changed.");
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
      toast.success(`Email changed to ${r.email}.`);
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
      toast.success("Two-factor authentication enabled.");
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
      toast.success("Two-factor authentication disabled.");
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
      toast.success("New recovery codes generated.");
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
      toast.success("Passkey added.");
      await refreshPasskeys();
    } catch (err) {
      if (err?.name !== "NotAllowedError") toast.error(err.message);
    } finally {
      pkBusy = false;
    }
  }

  async function removePasskey(id) {
    const pw = window.prompt("Confirm your password to remove this passkey:");
    if (!pw) return;
    try {
      await passkey.remove(id, pw);
      toast.success("Passkey removed.");
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
      toast.success("Recovery codes copied.");
    } catch {
      toast.error("Copy failed - select and copy manually.");
    }
  }
</script>

<div class="container">
  {#if ready}
    <div class="card">
      <h2>Account</h2>
      <p class="muted">
        Signed in as <code>{sessionState.user?.email}</code>
        ({sessionState.user?.role}).
      </p>
    </div>

    {#if isLocal}
      <div class="card">
        <h3>Change password</h3>
        <form onsubmit={doChangePassword}>
          <div class="field">
            <label for="cur">Current password</label>
            <input id="cur" class="input" type="password" bind:value={curPw}/>
          </div>
          <div class="field">
            <label for="new">New password</label>
            <input id="new" class="input" type="password" bind:value={newPw}/>
          </div>
          <button class="btn primary" type="submit" disabled={!curPw || !newPw}>
            Update password
          </button>
        </form>
      </div>

      <div class="card">
        <h3>Change email</h3>
        <form onsubmit={doChangeEmail}>
          <div class="field">
            <label for="ne">New email</label>
            <input id="ne" class="input" type="email" bind:value={newEmail}/>
          </div>
          <div class="field">
            <label for="ep">Current password</label>
            <input id="ep" class="input" type="password" bind:value={emailPw}/>
          </div>
          <button class="btn primary" type="submit" disabled={!newEmail || !emailPw}>
            Update email
          </button>
        </form>
      </div>

      <div class="card">
        <h3>Two-factor authentication</h3>
        {#if recoveryCodes}
          <div class="banner ok">
            Save these one-time recovery codes somewhere safe - each works
            once if you lose your authenticator.
          </div>
          <pre class="codes mono">{recoveryCodes.join("\n")}</pre>
          <button class="btn" onclick={copyCodes}>Copy codes</button>
        {:else if setup}
          <p class="muted">
            Scan this QR code with your authenticator app (or enter the
            secret manually), then enter the 6-digit code to confirm.
          </p>
          <img
            class="qr"
            src={"data:image/png;base64," + setup.qr_png_base64}
            alt="TOTP QR code"
            width="200"
            height="200"
          />
          <div class="field">
            <span class="muted">Secret (manual entry)</span>
            <code class="mono">{setup.secret}</code>
          </div>
          <form onsubmit={confirmTwoFA}>
            <div class="field">
              <label for="cc">Code</label>
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
              Enable 2FA
            </button>
          </form>
        {:else if sessionState.user?.totp_enabled}
          <div class="banner ok">
            Your account is protected by an authenticator app.
          </div>
          <form onsubmit={disableTwoFA}>
            <div class="field">
              <label for="tp">Confirm password</label>
              <input id="tp" class="input" type="password" bind:value={twofaPw}/>
            </div>
            <div class="row">
              <button class="btn" onclick={regenCodes} disabled={!twofaPw}>
                Regenerate recovery codes
              </button>
              <button class="btn danger" type="submit" disabled={!twofaPw}>
                Disable 2FA
              </button>
            </div>
          </form>
        {:else}
          <p class="muted">
            Add a second factor with an authenticator app (local password
            accounts only).
          </p>
          <form onsubmit={startTwoFA}>
            <div class="field">
              <label for="t2p">Confirm password</label>
              <input id="t2p" class="input" type="password" bind:value={twofaPw}/>
            </div>
            <button class="btn primary" type="submit" disabled={!twofaPw}>
              Set up 2FA
            </button>
          </form>
        {/if}
      </div>

      {#if passkeySupported}
        <div class="card">
          <h3>Passkeys</h3>
          {#if passkeys.length === 0}
            <p class="muted">No passkeys yet.</p>
          {:else}
            <table class="tbl">
              <thead>
              <tr>
                <th>Name</th>
                <th>Added</th>
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
                      Remove
                    </button>
                  </td>
                </tr>
              {/each}
              </tbody>
            </table>
          {/if}
          <form onsubmit={addPasskey} style="margin-top:12px">
            <div class="field">
              <label for="pkn">Name (to recognize this device)</label>
              <input id="pkn" class="input" bind:value={pkName} placeholder="e.g. MacBook Touch ID"/>
            </div>
            <div class="field">
              <label for="pkp">Confirm password</label>
              <input id="pkp" class="input" type="password" bind:value={pkPw}/>
            </div>
            <button class="btn primary" type="submit" disabled={pkBusy || !pkPw}>
              {pkBusy ? "Waiting for authenticator…" : "Add passkey"}
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
