<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { buildQuery, errorMessage, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import type { CreateResponse, Id } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);

	let filterName = $state('');
	let filterDescription = $state('');

	// Re-sync the filter inputs whenever fresh data arrives (navigation, invalidateAll).
	$effect.pre(() => {
		const f = data.template.filters;
		filterName = f.name ?? '';
		filterDescription = f.description ?? '';
	});

	async function runSearch() {
		await goto(
			`/group${buildQuery({
				name: filterName.trim(),
				description: filterDescription.trim()
			})}`
		);
	}

	async function runReset() {
		await goto('/group');
	}

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	let newGroupName = $state('');
	let newGroupDescription = $state('');
	let formError = $state<string | null>(null);

	async function createGroup(event: SubmitEvent) {
		event.preventDefault();
		formError = null;
		try {
			const res = await sendForm<CreateResponse>('POST', '/group/create', {
				name: newGroupName,
				description: newGroupDescription
			});
			await goto(`/group/${res.id}`);
		} catch (err) {
			formError = errorMessage(err);
		}
	}

	async function deleteGroup(id: Id) {
		if (!confirm('Are you sure you want to delete this group?')) return;
		formError = null;
		try {
			await sendForm('DELETE', `/group/${id}`);
			await invalidateAll();
		} catch (err) {
			formError = errorMessage(err);
		}
	}
</script>

<svelte:head>
	<title>edumdns - Groups</title>
</svelte:head>

<div class="lg:w-3/4 w-full mx-auto mb-10 md:mb-5">
	<!-- Header Section -->
	<div class="flex flex-col justify-center items-center py-6">
		<h2 class="text-4xl font-bold text-sat-xl">Groups</h2>
	</div>

	<!-- New Group -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-6">
		<h3 class="text-2xl font-semibold text-sat-l mb-4">New Group</h3>
		<form class="grid grid-cols-1 md:grid-cols-2 gap-4" onsubmit={createGroup}>
			<div class="flex flex-col">
				<label for="name" class="text-xs uppercase tracking-wide text-sat-l">Name</label>
				<input
					id="name"
					name="name"
					type="text"
					required
					class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc"
					placeholder="Enter group name"
					bind:value={newGroupName}
				/>
			</div>
			<div class="flex flex-col md:col-span-2">
				<label for="description" class="text-xs uppercase tracking-wide text-sat-m">Description</label>
				<textarea
					id="description"
					name="description"
					rows="3"
					class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc"
					placeholder="Optional description"
					bind:value={newGroupDescription}
				></textarea>
			</div>
			<div class="md:col-span-2">
				<button
					type="submit"
					class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-cards hover:bg-acc-xl transition-colors"
				>
					Create Group
				</button>
			</div>
		</form>
		<ErrorAlert message={formError} class="mt-3" />
	</div>

	<div class="overflow-x-auto rounded-lg border border-base bg-cards">
		<table class="w-full divide-y divide-base">
			<thead class="bg-muted/10">
				<tr>
					<th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th>
					<th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th>
					<th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Description</th>
					<th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th>
				</tr>
				<tr>
					<td class="px-4 py-2"></td>
					<td class="px-4 py-2"><input type="text" id="filter-name" bind:value={filterName} onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())} class="w-full rounded-md border border-base px-2 py-1 text-sm" /></td>
					<td class="px-4 py-2"><input type="text" id="filter-description" bind:value={filterDescription} onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())} class="w-full rounded-md border border-base px-2 py-1 text-sm" /></td>
					<td class="px-4 py-2 flex gap-2">
						<button type="button" id="filter-button" onclick={runSearch} class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button>
						<button type="button" id="reset-button" onclick={runReset} class="px-3 py-1 rounded-md text-button text-sm bg-acc-l hover:bg-muted/20 transition-colors">Reset</button>
					</td>
				</tr>
			</thead>

			<tbody class="divide-y divide-base">
				{#each template.groups as group (group.id)}
					<tr class="cursor-pointer rounded-lg bg-table transition-colors" onclick={(e) => handleRowClick(e, `/group/${group.id}`)}>
						<td class="px-4 py-3 font-mono text-sm text-sat-l">
							<a href="/group/{group.id}" class="text-primary hover:underline">{group.id}</a>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">{group.name}</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							{#if group.description}
								{group.description}
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">
							<button
								type="button"
								onclick={() => deleteGroup(group.id)}
								class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
								title="Delete group"
							>
								<i class="fa-solid fa-trash"></i>
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>

		{#if template.groups.length === 0}
			<div class="p-6 text-center text-muted-foreground">No groups found.</div>
		{/if}
	</div>
</div>
