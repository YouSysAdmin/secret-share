<script>
  import {page} from "$app/stores";
  import {base, secrets} from "$lib/api.js";
  import {toast} from "$lib/stores/toast.svelte.js";
  import {decryptFromPayload, decryptWithPassphrase} from "$lib/crypto.js";
  import {t, tn} from "$lib/i18n.svelte.js";

  const id = $derived($page.params.id);

  let loading = $state(true);
  let meta = $state(null); // { exists, views_remaining? }
  let fragKey = $state(""); // decryption key from the URL fragment
  let passMode = $state(false); // #p fragment: passphrase-protected
  let passphrase = $state("");
  let revealed = $state(null); // ciphertext kept in memory for passphrase retries
  let decrypting = $state(false);
  let revealing = $state(false);
  let plaintext = $state(null);
  let done = $state(false); // revealed
  let viewsLeft = $state(0); // >0 when the secret survives this view (multi-view)

  $effect(() => {
    // Read the fragment before anything else: #k=<key> carries the embedded key.
    // a bare #p marks a passphrase-protected secret (no key in the URL).
    if (typeof window !== "undefined") {
      const hash = window.location.hash || "";
      const m = hash.match(/(?:^#|[#&])k=([^&]+)/);
      fragKey = m ? decodeURIComponent(m[1]) : "";
      passMode = !fragKey && /(?:^#|[#&])p(?:=|&|$)/.test(hash);
    }
    load();
  });

  async function load() {
    loading = true;
    try {
      meta = await secrets.meta(id);
    } catch (e) {
      toast.error(e.message);
      meta = {exists: false};
    } finally {
      loading = false;
    }
  }

  async function reveal() {
    revealing = true;
    try {
      const r = await secrets.reveal(id);
      viewsLeft = r.views_remaining || 0;
      if (passMode) {
        // The secret is burned server-side now; keep the ciphertext in memory
        // so a mistyped passphrase can be retried without losing it.
        revealed = r.ciphertext;
        await tryDecrypt();
        return;
      }
      if (!fragKey) {
        toast.error(t("reveal.missingKey"));
        return;
      }
      plaintext = await decryptFromPayload(r.ciphertext, fragKey);
      done = true;
    } catch (e) {
      toast.error(e.message);
      await load();
    } finally {
      revealing = false;
    }
  }

  async function tryDecrypt() {
    if (!passphrase) {
      toast.error(t("common.enterPassphrase"));
      return;
    }
    decrypting = true;
    try {
      plaintext = await decryptWithPassphrase(revealed, passphrase);
      done = true;
    } catch {
      toast.error(t("reveal.wrongPassphrase"));
    } finally {
      decrypting = false;
    }
  }

  async function submitPassphrase(e) {
    e.preventDefault();
    if (!passphrase) {
      // Don't burn the secret on an empty submit.
      toast.error(t("common.enterPassphrase"));
      return;
    }
    if (revealed) {
      await tryDecrypt();
    } else {
      await reveal();
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(plaintext);
      toast.success(t("common.copied"));
    } catch {
      toast.error(t("common.copyFailed"));
    }
  }
</script>

<div class="container">
  <div class="card">
    {#if loading}
      <p class="muted">{t("common.loading")}</p>
    {:else if done}
      <h2>{t("reveal.title")}</h2>
      <p class="muted">
        {#if viewsLeft > 0}
          {tn("reveal.viewsLeft", viewsLeft)}
        {:else}
          {t("reveal.deleted")}
        {/if}
      </p>
      <div class="secret-box">{plaintext}</div>
      <div style="margin-top:1rem" class="row">
        <button class="btn primary" onclick={copy}>{t("common.copy")}</button>
        <a class="btn" href="{base}/">{t("common.shareYourOwn")}</a>
      </div>
    {:else if revealed}
      <h2>{t("reveal.passEnterTitle")}</h2>
      <p class="muted">
        {#if viewsLeft > 0}
          {tn("reveal.passRetrievedLeft", viewsLeft)}
        {:else}
          {t("reveal.passRetrievedGone")}
        {/if}
        {t("reveal.passEnterTail")}
      </p>
      <form onsubmit={submitPassphrase}>
        <div class="field">
          <label for="passphrase">{t("common.passphrase")}</label>
          <input
            id="passphrase"
            class="input"
            type="password"
            bind:value={passphrase}
            autocomplete="off"
          />
        </div>
        <button class="btn primary block" type="submit" disabled={decrypting}>
          {decrypting ? t("common.decrypting") : t("common.decrypt")}
        </button>
      </form>
    {:else if !meta?.exists}
      <h2>{t("reveal.unavailableTitle")}</h2>
      <p class="muted info">
        {t("reveal.unavailableBody")}
      </p>
      <a class="btn primary" href="{base}/">{t("common.shareASecret")}</a>
    {:else if passMode}
      <h2>{t("reveal.passTitle")}</h2>
      <p class="muted">
        {t("reveal.passBody")}
      </p>
      <form onsubmit={submitPassphrase}>
        <div class="field">
          <label for="passphrase">{t("common.passphrase")}</label>
          <input
            id="passphrase"
            class="input"
            type="password"
            bind:value={passphrase}
            autocomplete="off"
          />
        </div>
        <button class="btn primary block" type="submit" disabled={revealing}>
          {revealing ? t("reveal.buttonBusy") : t("reveal.button")}
        </button>
      </form>
    {:else if !fragKey}
      <h2>{t("reveal.incompleteTitle")}</h2>
      <p class="muted">
        {t("reveal.incompleteBody")}
      </p>
    {:else}
      <h2>{t("reveal.receivedTitle")}</h2>
      <p class="muted">
        {#if meta?.views_remaining > 1}
          {tn("reveal.receivedBodyMulti", meta.views_remaining)}
        {:else}
          {t("reveal.receivedBody")}
        {/if}
      </p>
      <button
        class="btn primary block"
        onclick={reveal}
        disabled={revealing}
      >
        {revealing ? t("reveal.buttonBusy") : t("reveal.button")}
      </button>
    {/if}
  </div>
</div>
