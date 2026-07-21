<script>
  import {page} from "$app/stores";
  import {base, files} from "$lib/api.js";
  import {toast} from "$lib/stores/toast.svelte.js";
  import {
    decryptBytes,
    decryptBytesWithPassphrase,
    unpackFilePayload,
  } from "$lib/crypto.js";
  import {t} from "$lib/i18n.svelte.js";

  const id = $derived($page.params.id);

  let loading = $state(true);
  let meta = $state(null); // { exists, size }
  let fragKey = $state("");
  let passMode = $state(false);
  let passphrase = $state("");
  let revealed = $state(null); // encrypted bytes kept in memory for passphrase retries
  let decrypting = $state(false);
  let revealing = $state(false);
  let fileOut = $state(null); // { name, size, url } once decrypted
  let done = $state(false);

  $effect(() => {
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
      meta = await files.meta(id);
    } catch (e) {
      toast.error(e.message);
      meta = {exists: false};
    } finally {
      loading = false;
    }
  }

  function finish(packed) {
    const {name, type, bytes} = unpackFilePayload(packed);
    const blob = new Blob([bytes], {type});
    fileOut = {name, size: bytes.length, url: URL.createObjectURL(blob)};
    done = true;
  }

  async function reveal() {
    revealing = true;
    try {
      const blob = await files.reveal(id);
      if (passMode) {
        // Burned server-side; keep the ciphertext in memory so a mistyped
        // passphrase can be retried without losing the file.
        revealed = blob;
        await tryDecrypt();
        return;
      }
      if (!fragKey) {
        toast.error(t("reveal.missingKey"));
        return;
      }
      finish(await decryptBytes(blob, fragKey));
    } catch (e) {
      toast.error(e.message);
      await load();
    } finally {
      revealing = false;
    }
  }

  async function tryDecrypt() {
    decrypting = true;
    try {
      finish(await decryptBytesWithPassphrase(revealed, passphrase));
    } catch {
      toast.error(t("file.wrongPassphrase"));
    } finally {
      decrypting = false;
    }
  }

  async function submitPassphrase(e) {
    e.preventDefault();
    if (!passphrase) {
      // Don't burn the file on an empty submit.
      toast.error(t("common.enterPassphrase"));
      return;
    }
    if (revealed) {
      await tryDecrypt();
    } else {
      await reveal();
    }
  }

  function prettySize(n) {
    if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    if (n >= 1024) return `${Math.round(n / 1024)} KB`;
    return `${n} B`;
  }
</script>

<div class="container">
  <div class="card">
    {#if loading}
      <p class="muted">{t("common.loading")}</p>
    {:else if done}
      <h2>{t("file.readyTitle")}</h2>
      <p class="muted">
        {t("file.readyBody")}
      </p>
      <div class="secret-box">{fileOut.name} ({prettySize(fileOut.size)})</div>
      <div style="margin-top:1rem" class="row">
        <a class="btn primary" href={fileOut.url} download={fileOut.name}>
          {t("file.download")}
        </a>
        <a class="btn" href="{base}/">{t("common.shareYourOwn")}</a>
      </div>
    {:else if revealed}
      <h2>{t("reveal.passEnterTitle")}</h2>
      <p class="muted">
        {t("file.passRetrieved")}
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
      <h2>{t("file.unavailableTitle")}</h2>
      <p class="muted info">
        {t("file.unavailableBody")}
      </p>
      <a class="btn primary" href="{base}/">{t("common.shareASecret")}</a>
    {:else if passMode}
      <h2>{t("file.passTitle")}</h2>
      <p class="muted">
        {t("file.passBody", {size: prettySize(meta.size || 0)})}
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
          {revealing ? t("file.retrieving") : t("file.retrieve")}
        </button>
      </form>
    {:else if !fragKey}
      <h2>{t("reveal.incompleteTitle")}</h2>
      <p class="muted">
        {t("reveal.incompleteBody")}
      </p>
    {:else}
      <h2>{t("file.receivedTitle")}</h2>
      <p class="muted">
        {t("file.receivedBody", {size: prettySize(meta.size || 0)})}
      </p>
      <button
        class="btn primary block"
        onclick={reveal}
        disabled={revealing}
      >
        {revealing ? t("file.retrieving") : t("file.retrieve")}
      </button>
    {/if}
  </div>
</div>
