<script>
    import { base, secrets, config } from "$lib/api.js";
    import { toast } from "$lib/stores/toast.svelte.js";
    import { encryptToPayload } from "$lib/crypto.js";

    let cfg = $state(null);
    let text = $state("");
    let ttlPreset = $state(""); // a preset value, or "custom"
    let customValue = $state(1);
    let customUnit = $state("h"); // m | h | d
    let busy = $state(false);
    let result = $state(null); // { url }

    const presets = $derived(
        cfg?.allowed_ttls?.length
            ? cfg.allowed_ttls
            : ["5m", "1h", "24h", "168h"],
    );

    $effect(() => {
        config()
            .then((c) => {
                cfg = c;
                ttlPreset = c.default_ttl || "24h";
            })
            .catch(() => {
                ttlPreset = "24h";
            });
    });

    const presetLabels = {
        "5m": "5 minutes",
        "1h": "1 hour",
        "24h": "1 day",
        "168h": "7 days",
    };
    const presetLabel = (t) => presetLabels[t] || t;

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
        if (!text.trim()) {
            toast.error("Enter a secret first.");
            return;
        }
        const ttl = resolveTTL();
        if (!ttl) {
            toast.error("Enter a valid custom lifetime.");
            return;
        }
        busy = true;
        try {
            const { ciphertext, key } = await encryptToPayload(text);
            const res = await secrets.create({ ttl, ciphertext });
            result = {
                url: `${window.location.origin}${base}/s/${res.id}#k=${key}`,
            };
            text = "";
        } catch (err) {
            toast.error(err.message);
        } finally {
            busy = false;
        }
    }

    async function copy() {
        try {
            await navigator.clipboard.writeText(result.url);
            toast.success("Link copied.");
        } catch {
            toast.error("Copy failed — select and copy manually.");
        }
    }

    function reset() {
        result = null;
    }
</script>

<div class="container">
    {#if result}
        <div class="card">
            <h2>Your link is ready</h2>
            <p class="muted">
                This link reveals the secret once, then it's gone. It also
                expires automatically. The decryption key is in the link after <code
                    >#</code
                > and never reached our server.
            </p>
            <div class="link-row">
                <input
                    class="input"
                    readonly
                    value={result.url}
                    onclick={(e) => e.target.select()}
                />
                <button class="btn primary" onclick={copy}>Copy</button>
            </div>
            <div style="margin-top:1rem">
                <button class="btn" onclick={reset}>Share another</button>
            </div>
        </div>
    {:else}
        <div class="card">
            <h2>Share a secret</h2>
            <p class="muted">
                End-to-end encrypted in your browser — we can't read it. Anyone
                with the link can view it once, then it's deleted.
            </p>
            <form onsubmit={submit}>
                <div class="field">
                    <label for="secret">Secret</label>
                    <textarea
                        id="secret"
                        class="input"
                        bind:value={text}
                        placeholder="Paste a password, token, or any text…"
                    ></textarea>
                </div>

                <div class="field">
                    <label for="ttl">Lifetime</label>
                    <select id="ttl" class="input" bind:value={ttlPreset}>
                        {#each presets as t (t)}
                            <option value={t}>{presetLabel(t)}</option>
                        {/each}
                        <option value="custom">Custom…</option>
                    </select>
                </div>

                {#if ttlPreset === "custom"}
                    <div class="field">
                        <label for="custom">Custom lifetime</label>
                        <div class="row">
                            <input
                                id="custom"
                                class="input"
                                type="number"
                                min="1"
                                bind:value={customValue}
                                style="max-width:120px"
                            />
                            <select
                                class="input"
                                bind:value={customUnit}
                                style="max-width:140px"
                            >
                                <option value="m">minutes</option>
                                <option value="h">hours</option>
                                <option value="d">days</option>
                            </select>
                        </div>
                    </div>
                {/if}
                <button class="btn primary block" type="submit" disabled={busy}>
                    {busy ? "Creating…" : "Create link"}
                </button>
            </form>
        </div>
    {/if}
</div>
