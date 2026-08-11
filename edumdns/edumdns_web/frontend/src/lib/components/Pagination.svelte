<script lang="ts">
	import type { PageInfo } from '$lib/types';
	import { buildQuery, type QueryValue } from '$lib/api';

	let {
		pageInfo,
		basePath,
		filters = {}
	}: {
		pageInfo: PageInfo;
		basePath: string;
		filters?: Record<string, QueryValue>;
	} = $props();

	function href(page: number): string {
		return `${basePath}${buildQuery({ ...filters, page })}`;
	}

	/** Mirrors the template: current page plus two neighbours on each side, clamped. */
	const pages = $derived.by(() => {
		const out: number[] = [];
		for (const p2 of [pageInfo.page - 2, pageInfo.page - 1, pageInfo.page, pageInfo.page + 1, pageInfo.page + 2]) {
			if (p2 >= 1 && p2 <= pageInfo.total_pages) out.push(p2);
		}
		return out;
	});
</script>

{#if pageInfo.total_pages > 1}
	<div class="flex flex-wrap justify-center items-center mt-6 gap-2">
		{#if pageInfo.page > 1}
			<a
				href={href(pageInfo.page - 1)}
				class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors"
			>
				Prev
			</a>
		{/if}

		{#if pageInfo.page > 4}
			<a
				href={href(1)}
				class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors"
			>
				1
			</a>
		{/if}

		{#if pageInfo.page > 4}
			<span class="px-3 py-1 rounded-md border border-base text-sm">...</span>
		{/if}

		{#each pages as p (p)}
			{#if p === pageInfo.page}
				<span class="px-3 py-1 rounded-md bg-primary text-white text-sm">{p}</span>
			{:else}
				<a
					href={href(p)}
					class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors"
				>
					{p}
				</a>
			{/if}
		{/each}

		{#if pageInfo.page < pageInfo.total_pages - 3}
			<span class="px-3 py-1 rounded-md border border-base text-sm">...</span>
		{/if}

		{#if pageInfo.page < pageInfo.total_pages - 2}
			<a
				href={href(pageInfo.total_pages)}
				class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors"
			>
				{pageInfo.total_pages}
			</a>
		{/if}

		{#if pageInfo.page < pageInfo.total_pages}
			<a
				href={href(pageInfo.page + 1)}
				class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors"
			>
				Next
			</a>
		{/if}
	</div>
{/if}
