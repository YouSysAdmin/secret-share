<script>
    import { toasts, dismiss } from "$lib/stores/toast.svelte.js";
    const items = $derived(toasts());
</script>

<div class="toaster">
    {#each items as t (t.id)}
        <button
            type="button"
            class="toast {t.kind}"
            onclick={() => dismiss(t.id)}
        >
            {t.message}
        </button>
    {/each}
</div>
