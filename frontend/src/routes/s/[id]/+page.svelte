<script>
  import {page} from "$app/stores";
  import {base, secrets} from "$lib/api.js";
  import {toast} from "$lib/stores/toast.svelte.js";
  import {decryptFromPayload} from "$lib/crypto.js";

  const id = $derived($page.params.id);

  let loading = $state(true);
  let meta = $state(null); // { exists }
  let fragKey = $state(""); // decryption key from the URL fragment
  let revealing = $state(false);
  let plaintext = $state(null);
  let done = $state(false); // burned

  $effect(() => {
    // Read the fragment key before anything else.
    if (typeof window !== "undefined") {
      const m = (window.location.hash || "").match(
        /(?:^#|[#&])k=([^&]+)/,
      );
      fragKey = m ? decodeURIComponent(m[1]) : "";
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
      if (!fragKey) {
        toast.error("This link is missing its decryption key.");
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

  async function copy() {
    try {
      await navigator.clipboard.writeText(plaintext);
      toast.success("Copied.");
    } catch {
      toast.error("Copy failed - select and copy manually.");
    }
  }
</script>

<div class="container">
  <div class="card">
    {#if loading}
      <p class="muted">Loading…</p>
    {:else if done}
      <h2>Secret</h2>
      <p class="muted">
        This secret has now been deleted and can't be viewed again.
      </p>
      <div class="secret-box">{plaintext}</div>
      <div style="margin-top:1rem" class="row">
        <button class="btn primary" onclick={copy}>Copy</button>
        <a class="btn" href="{base}/">Share your own</a>
      </div>
    {:else if !meta?.exists}
      <h2>Secret unavailable</h2>
      <p class="muted info">
        This secret has already been viewed, has expired, or never
        existed. Secrets are one-time and disappear after the first
        view.
      </p>
      <a class="btn primary" href="{base}/">Share a secret</a>
    {:else if !fragKey}
      <h2>Incomplete link</h2>
      <p class="muted">
        This link is missing its decryption key (the part after <code
      >#</code
      >). Ask the sender for the complete link.
      </p>
    {:else}
      <h2>You've received a secret</h2>
      <p class="muted">
        Viewing it will permanently delete it - you can only see it
        once. Make sure you're ready.
      </p>
      <button
        class="btn primary block"
        onclick={reveal}
        disabled={revealing}
      >
        {revealing ? "Revealing…" : "Reveal secret"}
      </button>
    {/if}
  </div>
</div>
