<script lang="ts">
	let {
		message,
		class: className = 'mb-3'
	}: {
		message: string | null | undefined;
		class?: string;
	} = $props();
</script>

{#if message}
	<div id="error-area" class="text-error {className}">{message}</div>
{/if}
