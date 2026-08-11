<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { buildQuery, errorMessage, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import type { CreateResponse } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);

	const pageFilters = $derived({
		id: template.filters.id,
		owner_id: template.filters.owner_id,
		location_id: template.filters.location_id,
		adopted: template.filters.adopted,
		mac: template.filters.mac,
		ip: template.filters.ip,
		name: template.filters.name
	});

	let filterId = $state('');
	let filterName = $state('');
	let filterOwnerId = $state('');
	let filterMac = $state('');
	let filterIp = $state('');
	let filterAdopted = $state('');

	// Re-sync the filter inputs whenever fresh data arrives (navigation, invalidateAll).
	$effect.pre(() => {
		const f = data.template.filters;
		filterId = f.id ?? '';
		filterName = f.name ?? '';
		filterOwnerId = f.owner_id != null ? String(f.owner_id) : '';
		filterMac = f.mac ?? '';
		filterIp = f.ip ?? '';
		filterAdopted = f.adopted === true ? 'true' : f.adopted === false ? 'false' : '';
	});

	async function runSearch() {
		await goto(
			`/probe${buildQuery({
				id: filterId.trim(),
				name: filterName.trim(),
				owner_id: filterOwnerId.trim(),
				mac: filterMac.trim(),
				ip: filterIp.trim(),
				adopted: filterAdopted
			})}`
		);
	}

	async function runReset() {
		await goto('/probe');
	}

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	let newProbeName = $state('');
	let createError = $state<string | null>(null);
	let createdId = $state<string | null>(null);

	async function createProbe(event: SubmitEvent) {
		event.preventDefault();
		createError = null;
		createdId = null;
		try {
			const res = await sendForm<CreateResponse>('POST', '/probe/create', {
				name: newProbeName
			});
			createdId = String(res.id);
			newProbeName = '';
			await invalidateAll();
		} catch (err) {
			createError = errorMessage(err);
		}
	}
</script>

<svelte:head>
	<title>edumdns - Probes</title>
</svelte:head>

<div class="w-full mx-auto mb-10 md:mb-5">
	<div class="flex flex-col justify-center items-center py-6">
		<h2 class="text-4xl font-bold text-sat-xl">Probes</h2>
	</div>

	{#if template.user.has_groups || template.user.user.admin}
		<!-- New Probe -->
		<div class="rounded-lg border border-base bg-cards p-6 mb-6">
			<h3 class="text-2xl font-semibold text-forms mb-4">New Probe</h3>
			<form class="grid grid-cols-1 md:grid-cols-2 gap-4" onsubmit={createProbe}>
				<div class="flex flex-col">
					<label for="name" class="text-xs uppercase text-forms tracking-wide">Name</label>
					<input
						id="name"
						name="name"
						type="text"
						required
						class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc"
						placeholder="Enter probe name"
						bind:value={newProbeName}
					/>
				</div>
				<div class="md:col-span-2">
					<button
						type="submit"
						class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button hover:bg-acc-xl transition-colors"
					>
						Create Probe
					</button>
				</div>
			</form>
			<ErrorAlert message={createError} />
			{#if createdId}
				<div class="text-green-600 mt-3">
					Probe created. ID: <code class="font-mono">{createdId}</code>
				</div>
			{/if}
		</div>
	{/if}

	<div class="overflow-x-auto rounded-lg border border-base bg-cards">
		<table class="w-full divide-y divide-base">
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
						Name
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Owner
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
						Adopted
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						First Connected At
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Last Connected At
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs  text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
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
							id="filter-name"
							bind:value={filterName}
							onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
						/></td
					>
					<td class="px-4 py-2"
						><input
							type="text"
							id="filter-owner_id"
							bind:value={filterOwnerId}
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
					<td class="px-4 py-2">
						<select
							id="filter-adopted"
							class="w-full rounded-md border border-base px-2 py-1 text-sm"
							bind:value={filterAdopted}
							onchange={runSearch}
						>
							<option value="">All</option>
							<option value="true">Adopted</option>
							<option value="false">Not Adopted</option>
						</select>
					</td>
					<td class="px-4 py-2"></td>
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
				{#each template.probes as probe (probe.id)}
					<tr
						class="cursor-pointer rounded-lg bg-table transition-colors"
						onclick={(e) => handleRowClick(e, `/probe/${probe.id}`)}
					>
						<td class="px-4 py-3 font-mono text-sm text-sat-l whitespace-nowrap">
							<a href="/probe/{probe.id}" class="text-primary hover:underline">
								{probe.id}
							</a>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							{#if probe.name !== null}
								{probe.name}
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							{#if probe.owner_id !== null}
								<a href="/user/{probe.owner_id}">{probe.owner_id}</a>
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">{probe.mac}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{probe.ip}</td>
						<td class="px-4 py-3 text-sm">
							{#if probe.adopted}
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
						<td class="px-4 py-3 text-sm text-sat-l">{probe.first_connected_at}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{probe.last_connected_at}</td>
						<td class="px-4 py-3 text-sm text-sat-l"></td>
					</tr>
				{/each}
			</tbody>
		</table>

		{#if template.probes.length === 0}
			<div class="p-6 text-center text-muted-foreground">No probes found.</div>
		{/if}
	</div>

	<Pagination pageInfo={template.page_info} basePath="/probe" filters={pageFilters} />
</div>
