<script lang="ts">
	import { goto } from '$app/navigation';
	import { buildQuery } from '$lib/api';
	import Pagination from '$lib/components/Pagination.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);

	const pageFilters = $derived({
		id: template.filters.id,
		probe_id: template.filters.probe_id,
		src_mac: template.filters.src_mac,
		dst_mac: template.filters.dst_mac,
		src_addr: template.filters.src_addr,
		dst_addr: template.filters.dst_addr,
		src_port: template.filters.src_port,
		dst_port: template.filters.dst_port,
		payload_string: template.filters.payload_string
	});

	let filterId = $state('');
	let filterProbeId = $state('');
	let filterSrcMac = $state('');
	let filterDstMac = $state('');
	let filterSrcAddr = $state('');
	let filterDstAddr = $state('');
	let filterSrcPort = $state('');
	let filterDstPort = $state('');
	let filterPayloadString = $state('');

	// Re-sync the filter inputs whenever fresh data arrives (navigation, invalidateAll).
	$effect.pre(() => {
		const f = data.template.filters;
		filterId = f.id != null ? String(f.id) : '';
		filterProbeId = f.probe_id ?? '';
		filterSrcMac = f.src_mac ?? '';
		filterDstMac = f.dst_mac ?? '';
		filterSrcAddr = f.src_addr ?? '';
		filterDstAddr = f.dst_addr ?? '';
		filterSrcPort = f.src_port != null ? String(f.src_port) : '';
		filterDstPort = f.dst_port != null ? String(f.dst_port) : '';
		filterPayloadString = f.payload_string ?? '';
	});

	async function runSearch() {
		await goto(
			`/packet${buildQuery({
				id: filterId.trim(),
				probe_id: filterProbeId.trim(),
				src_mac: filterSrcMac.trim(),
				dst_mac: filterDstMac.trim(),
				src_addr: filterSrcAddr.trim(),
				dst_addr: filterDstAddr.trim(),
				src_port: filterSrcPort.trim(),
				dst_port: filterDstPort.trim(),
				payload_string: filterPayloadString.trim()
			})}`
		);
	}

	async function runReset() {
		await goto('/packet');
	}

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	const thClass =
		'px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-sat-l text-muted-foreground';
</script>

<svelte:head>
	<title>edumdns - Packets</title>
</svelte:head>

<div class="w-full mx-auto mb-10 md:mb-5">
	<!-- Header Section -->
	<div class="flex flex-col justify-center items-center py-6">
		<h2 class="text-4xl font-bold text-sat-xl">Packets</h2>
	</div>

	<div class="overflow-x-auto rounded-lg border border-base bg-cards">
		<table class="divide-y divide-base">
			<thead class="bg-muted/10">
				<tr>
					<th scope="col" class={thClass}>ID</th>
					<th scope="col" class={thClass}>Probe</th>
					<th scope="col" class={thClass}>Source MAC</th>
					<th scope="col" class={thClass}>Destination MAC</th>
					<th scope="col" class={thClass}>Source IP</th>
					<th scope="col" class={thClass}>Destination IP</th>
					<th scope="col" class={thClass}>Source Port</th>
					<th scope="col" class={thClass}>Destination Port</th>
					<th scope="col" class={thClass}>Payload</th>
					<th scope="col" class={thClass}>Captured At</th>
					<th scope="col" class={thClass}>Actions</th>
				</tr>
				<tr>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-id"
							bind:value={filterId}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-probe_id"
							bind:value={filterProbeId}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-src_mac"
							bind:value={filterSrcMac}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-dst_mac"
							bind:value={filterDstMac}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-src_addr"
							bind:value={filterSrcAddr}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-dst_addr"
							bind:value={filterDstAddr}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-src_port"
							bind:value={filterSrcPort}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-dst_port"
							bind:value={filterDstPort}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-payload_string"
							bind:value={filterPayloadString}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"></td>
					<td class="px-4 py-2 flex gap-2">
						<button
							type="button"
							id="filter-button"
							onclick={runSearch}
							class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors"
						>
							Search
						</button>
						<button
							type="button"
							id="reset-button"
							onclick={runReset}
							class="px-3 py-1 rounded-md text-button text-sm bg-acc-l hover:bg-muted/20 transition-colors"
						>
							Reset
						</button>
					</td>
				</tr>
			</thead>
			<tbody class="divide-y">
				{#each template.packets as packet (packet.id)}
					<tr
						class="cursor-pointer rounded-lg bg-table transition-colors"
						onclick={(e) => handleRowClick(e, `/packet/${packet.id}`)}
					>
						<td class="px-4 py-3 font-mono text-sm">
							<a href="/packet/{packet.id}" class="text-primary hover:underline">
								{packet.id}
							</a>
						</td>
						<td class="px-4 py-3 font-mono text-sm">
							<a href="/probe/{packet.probe_id}" class="text-primary hover:underline">
								{packet.probe_id}
							</a>
						</td>

						<td class="px-4 py-3 text-sm text-sat-l font-mono">{packet.src_mac}</td>
						<td class="px-4 py-3 text-sm text-sat-l font-mono">{packet.dst_mac}</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							<span class="font-mono">{packet.src_addr}</span>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							<span class="font-mono">{packet.dst_addr}</span>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							<span class="font-mono">{packet.src_port}</span>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							<span class="font-mono">{packet.dst_port}</span>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							{#if packet.payload_string}
								<span class="font-mono">{packet.payload_string.slice(0, 42)}</span>
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							<span class="font-mono">{packet.captured_at ?? ''}</span>
						</td>
						<td class="px-4 py-2"></td>
					</tr>
				{/each}
			</tbody>
		</table>

		{#if template.packets.length === 0}
			<div class="p-6 text-center text-muted-foreground">No packets found.</div>
		{/if}
	</div>

	<Pagination pageInfo={template.page_info} basePath="/packet" filters={pageFilters} />
</div>
