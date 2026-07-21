<script>
  import {renderSVG} from "uqr";
  import {base, config, files, secrets, signinRedirect} from "$lib/api.js";
  import {toast} from "$lib/stores/toast.svelte.js";
  import {
    encryptBytes,
    encryptBytesWithPassphrase,
    encryptToPayload,
    encryptWithPassphrase,
    packFilePayload,
  } from "$lib/crypto.js";
  import {loadSession, sessionState,} from "$lib/stores/session.svelte.js";
  import {t, tn} from "$lib/i18n.svelte.js";

  let cfg = $state(null);
  let gated = $state(false);
  let text = $state("");
  let ttlPreset = $state(""); // a preset value, or "custom"
  let customValue = $state(1);
  let customUnit = $state("h"); // m | h | d
  let busy = $state(false);
  let result = $state(null); // { url, qr, passphraseProtected }
  let showQR = $state(false);
  let usePassphrase = $state(false);
  let passphrase = $state("");
  let views = $state(1);
  let mode = $state("text"); // text | file
  let pickedFile = $state(null);
  let fileEl = $state(null);

  const maxViews = $derived(cfg?.max_views > 1 ? cfg.max_views : 1);
  const filesEnabled = $derived(!!cfg?.files_enabled);
  const filesMaxBytes = $derived(cfg?.files_max_size_bytes || 0);

  function prettySize(n) {
    if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    if (n >= 1024) return `${Math.round(n / 1024)} KB`;
    return `${n} B`;
  }

  function onFilePick(e) {
    pickedFile = e.target.files?.[0] || null;
  }
  let visibility = $state("public"); // public | private (only when shown)

  // The public/private choice only matters when login is required to create but
  // revealing is otherwise open (gate=create). In "all" mode everything already
  // needs auth; in public mode there are no accounts to gate on.
  const showVisibility = $derived(
    !!cfg?.auth_enabled && cfg?.gate === "create",
  );

  const presets = $derived(
    cfg?.allowed_ttls?.length
      ? cfg.allowed_ttls
      : ["5m", "1h", "24h", "168h"],
  );

  $effect(() => {
    // Gate the form on auth: anonymous visitors are bounced to sign-in when
    // private mode is on (creating a secret always needs a session).
    loadSession().then(() => {
      if (sessionState.authEnabled && !sessionState.user) {
        signinRedirect();
        return;
      }
      gated = true;
    });
  });

  $effect(() => {
    config()
      .then((c) => {
        cfg = c;
        ttlPreset = c.default_ttl || "24h";
        // In private mode, default new secrets to Private (safer for org use);
        // the user can still switch to Public per secret.
        if (c.auth_enabled) visibility = "private";
      })
      .catch(() => {
        ttlPreset = "24h";
      });
  });

  // Known presets translate via ttl.* keys; anything else shows as-is.
  function presetLabel(p) {
    const label = t(`ttl.${p}`);
    return label === `ttl.${p}` ? p : label;
  }

  // Resolve the chosen lifetime to a Go duration string.
  function resolveTTL() {
    if (ttlPreset !== "custom") return ttlPreset;
    const n = Number(customValue);
    if (!Number.isFinite(n) || n <= 0) return null;
    if (customUnit === "m") return `${n}m`;
    if (customUnit === "d") return `${n * 24}h`;
    return `${n}h`;
  }

  async function submit(e) {
    e.preventDefault();
    const isFile = mode === "file";
    if (isFile && !pickedFile) {
      toast.error(t("create.errNoFile"));
      return;
    }
    if (!isFile && !text.trim()) {
      toast.error(t("create.errNoSecret"));
      return;
    }
    const ttl = resolveTTL();
    if (!ttl) {
      toast.error(t("create.errBadTTL"));
      return;
    }
    if (usePassphrase && passphrase.length < 6) {
      toast.error(t("create.errShortPassphrase"));
      return;
    }
    busy = true;
    try {
      const isPrivate = showVisibility && visibility === "private";
      if (isFile) {
        // Filename and type are packed with the content BEFORE encryption, so
        // they are as secret as the bytes themselves.
        const raw = new Uint8Array(await pickedFile.arrayBuffer());
        const packed = packFilePayload(
          pickedFile.name,
          pickedFile.type || "application/octet-stream",
          raw,
        );
        let blob, fragment;
        if (usePassphrase) {
          blob = await encryptBytesWithPassphrase(packed, passphrase);
          fragment = "#p";
        } else {
          let key;
          ({blob, key} = await encryptBytes(packed));
          fragment = `#k=${key}`;
        }
        if (filesMaxBytes && blob.length > filesMaxBytes) {
          toast.error(t("create.errFileTooLarge", {max: prettySize(filesMaxBytes)}));
          return;
        }
        const res = await files.create(blob, {ttl, private: isPrivate});
        const url = `${window.location.origin}${base}/f/${res.id}${fragment}`;
        result = {
          url,
          qr: renderSVG(url, {ecc: "M", border: 2}),
          passphraseProtected: usePassphrase,
          views: 1,
          isFile: true,
        };
        pickedFile = null;
      } else {
        // Passphrase mode derives the key from the passphrase (PBKDF2) so no key
        // rides the link - #p just tells the reveal page to prompt for it.
        let ciphertext, fragment;
        if (usePassphrase) {
          ({ciphertext} = await encryptWithPassphrase(text, passphrase));
          fragment = "#p";
        } else {
          let key;
          ({ciphertext, key} = await encryptToPayload(text));
          fragment = `#k=${key}`;
        }
        const nViews = Math.min(Math.max(Number(views) || 1, 1), maxViews);
        const res = await secrets.create({
          ttl,
          ciphertext,
          private: isPrivate,
          ...(nViews > 1 ? {views: nViews} : {}),
        });
        const url = `${window.location.origin}${base}/s/${res.id}${fragment}`;
        result = {
          url,
          // SVG QR of the full link (fragment included) - rendered locally, the
          // key never leaves the browser.
          qr: renderSVG(url, {ecc: "M", border: 2}),
          passphraseProtected: usePassphrase,
          views: nViews,
        };
        text = "";
      }
      showQR = false;
      passphrase = "";
      views = 1;
    } catch (err) {
      toast.error(err.message);
    } finally {
      busy = false;
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(result.url);
      toast.success(t("result.linkCopied"));
    } catch {
      toast.error(t("common.copyFailed"));
    }
  }

  function reset() {
    result = null;
  }
</script>

<div class="container">
  {#if gated}
    {#if result}
      <div class="card">
        <h2>{t("result.title")}</h2>
        <p class="muted">
          {#if result.isFile}
            {t("result.introFile")}
          {:else if result.views > 1}
            {tn("result.introMulti", result.views)}
          {:else}
            {t("result.introOne")}
          {/if}
          {result.passphraseProtected ? t("result.passNote") : t("result.keyNote")}
        </p>
        <div class="link-row">
          <input
            class="input"
            readonly
            value={result.url}
            onclick={(e) => e.target.select()}
          />
          <button class="btn primary" onclick={copy}>{t("common.copy")}</button>
        </div>
        <div style="margin-top:1rem" class="row">
          <button class="btn" onclick={() => (showQR = !showQR)}>
            {showQR ? t("result.hideQR") : t("result.showQR")}
          </button>
          <button class="btn" onclick={reset}>{t("result.shareAnother")}</button>
        </div>
        {#if showQR}
          <div class="qr-wrap">
            <!-- eslint-disable-next-line svelte/no-at-html-tags -- locally generated SVG, no user markup -->
            <div class="qr">{@html result.qr}</div>
          </div>
        {/if}
      </div>
    {:else}
      <div class="card">
        <h2>{t("create.title")}</h2>
        <p class="muted">
          {t("create.intro1")} <br/>
          {t("create.intro2")}
        </p>
        <form onsubmit={submit}>
          {#if filesEnabled}
            <div class="mode-tabs" role="tablist">
              <button
                type="button"
                class="btn tab"
                class:active={mode === "text"}
                onclick={() => (mode = "text")}
              >{t("create.tabText")}</button>
              <button
                type="button"
                class="btn tab"
                class:active={mode === "file"}
                onclick={() => (mode = "file")}
              >{t("create.tabFile")}</button>
            </div>
          {/if}

          {#if mode === "file" && filesEnabled}
            <div class="field">
              <label for="file">{t("create.fileLabel")}</label>
              <input
                bind:this={fileEl}
                id="file"
                class="file-input"
                type="file"
                onchange={onFilePick}
              />
              <button type="button" class="btn file-select" onclick={() => fileEl?.click()}>
                {pickedFile ? t("create.changeFile") : t("create.chooseFile")}
              </button>
              <p class="muted hint">
                {pickedFile
                  ? `${pickedFile.name} (${prettySize(pickedFile.size)})`
                  : t("create.fileHint", {max: prettySize(filesMaxBytes)})}
              </p>
            </div>
          {:else}
            <div class="field">
              <label for="secret">{t("create.secretLabel")}</label>
              <textarea
                id="secret"
                class="input"
                bind:value={text}
                placeholder={t("create.secretPlaceholder")}
              ></textarea>
            </div>
          {/if}

          <div class="field">
            <label for="ttl">{t("create.lifetime")}</label>
            <select id="ttl" class="input" bind:value={ttlPreset}>
              {#each presets as p (p)}
                <option value={p}>{presetLabel(p)}</option>
              {/each}
              <option value="custom">{t("create.customOption")}</option>
            </select>
          </div>

          {#if ttlPreset === "custom"}
            <div class="field">
              <label for="custom">{t("create.customLifetime")}</label>
              <div class="row">
                <input id="custom" class="input" type="number" min="1" bind:value={customValue}
                       style="max-width:120px"/>
                <select class="input" bind:value={customUnit} style="max-width:140px">
                  <option value="m">{t("create.minutes")}</option>
                  <option value="h">{t("create.hours")}</option>
                  <option value="d">{t("create.days")}</option>
                </select>
              </div>
            </div>
          {/if}

          {#if maxViews > 1 && mode !== "file"}
            <div class="field">
              <label for="views">{t("create.views")}</label>
              <input
                id="views"
                class="input"
                type="number"
                min="1"
                max={maxViews}
                bind:value={views}
                style="max-width:120px"
              />
              <p class="muted hint">
                {Number(views) > 1
                  ? t("create.viewsHintMulti", {n: views})
                  : t("create.viewsHintOne")}
              </p>
            </div>
          {/if}

          <div class="field">
            <label class="check">
              <input type="checkbox" bind:checked={usePassphrase}/>
              {t("create.passphraseToggle")}
            </label>
            <p class="muted hint">
              {usePassphrase
                ? t("create.passphraseHintOn")
                : t("create.passphraseHintOff")}
            </p>
          </div>

          {#if usePassphrase}
            <div class="field">
              <label for="passphrase">{t("common.passphrase")}</label>
              <input
                id="passphrase"
                class="input"
                type="password"
                bind:value={passphrase}
                placeholder={t("create.passphrasePlaceholder")}
                autocomplete="off"
              />
            </div>
          {/if}

          {#if showVisibility}
            <div class="field">
              <label for="visibility">{t("create.access")}</label>
              <select id="visibility" class="input" bind:value={visibility}>
                <option value="private">{t("create.private")}</option>
                <option value="public">{t("create.public")}</option>
              </select>
              <p class="muted hint">
                {visibility === "private"
                  ? t("create.accessHintPrivate")
                  : t("create.accessHintPublic")}
              </p>
            </div>
          {/if}
          <button class="btn primary block" type="submit" disabled={busy}>
            {busy ? t("create.submitBusy") : t("create.submit")}
          </button>
        </form>
      </div>
    {/if}
  {/if}
</div>

<style>
  .mode-tabs {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .tab {
    opacity: 0.65;
  }

  .tab.active {
    opacity: 1;
    outline: 2px solid currentColor;
    outline-offset: -2px;
  }

  .file-select {
    margin-bottom: 10px;
  }

  .file-input {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  .file-input:focus-visible + .btn {
    outline: 2px solid currentColor;
    outline-offset: 2px;
  }

  .check {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
  }

  .check input {
    width: auto;
    margin: 0;
  }

  .qr-wrap {
    margin-top: 1rem;
  }

  /* White backing regardless of theme: scanners want dark modules on light. */
  .qr {
    display: inline-block;
    padding: 0.5rem;
    background: #fff;
    border-radius: 8px;
    line-height: 0;
  }


  .qr :global(svg) {
    width: 192px;
    height: 192px;
    display: block;
  }
</style>
