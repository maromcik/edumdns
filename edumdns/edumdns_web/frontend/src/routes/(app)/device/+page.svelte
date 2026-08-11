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
		mac: template.filters.mac,
		ip: template.filters.ip,
		port: template.filters.port,
		name: template.filters.name,
		published: template.filters.published,
		proxy: template.filters.proxy,
		exclusive: template.filters.exclusive
	});

	let filterId = $state('');
	let filterProbeId = $state('');
	let filterName = $state('');
	let filterMac = $state('');
	let filterIp = $state('');
	let filterPort = $state('');
	let filterPublished = $state('');
	let filterExclusive = $state('');
	let filterProxy = $state('');

	// Re-sync the filter inputs whenever fresh data arrives (navigation, invalidateAll).
	$effect.pre(() => {
		const f = data.template.filters;
		filterId = f.id != null ? String(f.id) : '';
		filterProbeId = f.probe_id ?? '';
		filterName = f.name ?? '';
		filterMac = f.mac ?? '';
		filterIp = f.ip ?? '';
		filterPort = f.port != null ? String(f.port) : '';
		filterPublished = f.published === true ? 'true' : f.published === false ? 'false' : '';
		filterExclusive = f.exclusive === true ? 'true' : f.exclusive === false ? 'false' : '';
		filterProxy = f.proxy === true ? 'true' : f.proxy === false ? 'false' : '';
	});

	async function runSearch() {
		await goto(
			`/device${buildQuery({
				id: filterId.trim(),
				probe_id: filterProbeId.trim(),
				name: filterName.trim(),
				mac: filterMac.trim(),
				ip: filterIp.trim(),
				port: filterPort.trim(),
				published: filterPublished,
				exclusive: filterExclusive,
				proxy: filterProxy
			})}`
		);
	}

	async function runReset() {
		await goto('/device');
	}

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}
</script>

<svelte:head>
	<title>edumdns - Devices</title>
</svelte:head>

<div class="w-full mx-auto mb-10 md:mb-5">
	<div class="flex flex-col justify-center items-center py-6">
		<h2 class="text-4xl font-bold text-sat-xl">Devices</h2>
	</div>

	<div class="overflow-x-auto rounded-lg border border-base bg-cards">
		<table class="divide-y divide-base">
			<thead class="bg-muted/10">
				<tr>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						ID
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Probe
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Name
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						MAC
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						IP
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Port
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Published
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Exclusive
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Proxy
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Discovered At
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Actions
					</th>
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
							id="filter-name"
							bind:value={filterName}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-mac"
							bind:value={filterMac}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-ip"
							bind:value={filterIp}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-port"
							bind:value={filterPort}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2">
						<select
							id="filter-published"
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
							bind:value={filterPublished}
						>
							<option value="">All</option>
							<option value="true">Published</option>
							<option value="false">Not Published</option>
						</select>
					</td>
					<td class="px-4 py-2">
						<select
							id="filter-exclusive"
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
							bind:value={filterExclusive}
						>
							<option value="">All</option>
							<option value="true">Exclusive</option>
							<option value="false">Not Exclusive</option>
						</select>
					</td>
					<td class="px-4 py-2">
						<select
							id="filter-proxy"
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
							bind:value={filterProxy}
						>
							<option value="">All</option>
							<option value="true">Proxy</option>
							<option value="false">No Proxy</option>
						</select>
					</td>
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
							class="px-3 py-1 rounded-md text-sm bg-acc-l text-button hover:bg-muted/20 transition-colors"
						>
							Reset
						</button>
					</td>
				</tr>
			</thead>
			<tbody class="divide-y divide-base">
				{#each template.devices as device (device.id)}
					<tr
						class="cursor-pointer rounded-lg bg-table transition-colors"
						onclick={(e) => handleRowClick(e, `/device/${device.id}`)}
					>
						<td class="px-4 py-3 font-mono text-sm text-sat-l">
							<a href="/device/{device.id}" class="text-primary hover:underline">
								{device.id}
							</a>
						</td>
						<td class="px-4 py-3 text-sm">
							<a href="/probe/{device.probe_id}" class="text-primary hover:underline">
								{device.probe_id}
							</a>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							{#if device.name !== null}
								{device.name}
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">{device.mac}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{device.ip}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{device.port}</td>
						<td class="px-4 py-3 text-sm">
							{#if device.published}
								<span
									class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800"
									>Yes</span
								>
							{:else}
								<span
									class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800"
									>No</span
								>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm">
							{#if device.exclusive}
								<span
									class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800"
									>Yes</span
								>
							{:else}
								<span
									class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800"
									>No</span
								>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm">
							{#if device.proxy}
								<span
									class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800"
									>Yes</span
								>
							{:else}
								<span
									class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800"
									>No</span
								>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">{device.discovered_at}</td>
						<td class="px-4 py-2"></td>
					</tr>
				{/each}
			</tbody>
		</table>

		{#if template.devices.length === 0}
			<div class="p-6 text-center text-muted-foreground">No devices found.</div>
		{/if}
	</div>

	<Pagination pageInfo={template.page_info} basePath="/device" filters={pageFilters} />
</div>
