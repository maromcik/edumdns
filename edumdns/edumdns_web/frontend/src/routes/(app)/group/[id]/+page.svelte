<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { errorMessage, get, getAction, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import type { GenericError, GroupDetailUsersTemplate, Id, User } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const group = $derived(template.group);

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	/**
	 * BulkAddEntityForm is deserialized from repeated `entity_ids[]` form keys,
	 * which `sendForm` (plain object) cannot express — build the body manually.
	 */
	async function postEntityIds(path: string, ids: Id[]): Promise<void> {
		const body = new URLSearchParams();
		for (const id of ids) body.append('entity_ids[]', String(id));
		const res = await fetch(`/api${path}`, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString()
		});
		if (!res.ok) {
			let message = res.statusText;
			try {
				const err = (await res.json()) as Partial<GenericError>;
				if (err.description) message = err.description;
			} catch {
				// keep statusText fallback
			}
			throw new Error(message);
		}
	}

	// ---- Delete group ----
	let deleteError = $state<string | null>(null);

	async function deleteGroup() {
		if (!confirm('Are you sure you want to delete this group?')) return;
		deleteError = null;
		try {
			await sendForm('DELETE', `/group/${group.id}`);
			await goto('/group');
		} catch (err) {
			deleteError = errorMessage(err);
		}
	}

	// ---- Group settings form ----
	let editName = $state('');
	let editDescription = $state('');
	let settingsError = $state<string | null>(null);
	let settingsSaved = $state(false);

	$effect.pre(() => {
		const g = data.template.group;
		editName = g.name;
		editDescription = g.description ?? '';
	});

	async function saveSettings(event: SubmitEvent) {
		event.preventDefault();
		settingsError = null;
		settingsSaved = false;
		try {
			await sendForm('POST', '/group/update', {
				id: group.id,
				name: editName,
				description: editDescription
			});
			settingsSaved = true;
			await invalidateAll();
		} catch (err) {
			settingsError = errorMessage(err);
		}
	}

	function resetSettings() {
		editName = group.name;
		editDescription = group.description ?? '';
	}

	// ---- Add users: debounced live search ----
	let userSearch = $state('');
	let userResults = $state<User[]>([]);
	let userSearched = $state(false);
	let userSearchError = $state<string | null>(null);
	let selectedUserIds = $state<Id[]>([]);
	let addUsersError = $state<string | null>(null);
	let searchSeq = 0;

	async function runUserSearch(q: string) {
		const seq = ++searchSeq;
		try {
			const res = await get<GroupDetailUsersTemplate>(`/group/${group.id}/search`, { q });
			if (seq !== searchSeq) return;
			userResults = res.users;
			userSearchError = null;
			userSearched = true;
		} catch (err) {
			if (seq !== searchSeq) return;
			userResults = [];
			userSearchError = errorMessage(err);
			userSearched = true;
		}
	}

	$effect(() => {
		const q = userSearch.trim();
		if (!q) {
			searchSeq++;
			userResults = [];
			userSearchError = null;
			userSearched = false;
			return;
		}
		const timer = setTimeout(() => void runUserSearch(q), 300);
		return () => clearTimeout(timer);
	});

	function toggleUser(id: Id, checked: boolean) {
		selectedUserIds = checked ? [...selectedUserIds, id] : selectedUserIds.filter((x) => x !== id);
	}

	async function addUsers(event: SubmitEvent) {
		event.preventDefault();
		addUsersError = null;
		if (selectedUserIds.length === 0) return;
		try {
			await postEntityIds(`/group/${group.id}/users/add`, selectedUserIds);
			selectedUserIds = [];
			userSearch = '';
			await invalidateAll();
		} catch (err) {
			addUsersError = errorMessage(err);
		}
	}

	// ---- Remove user from the group ----
	let removeUserError = $state<string | null>(null);

	async function removeUser(userId: Id) {
		removeUserError = null;
		try {
			await getAction(`/group/${group.id}/users/${userId}/delete`);
			await invalidateAll();
		} catch (err) {
			removeUserError = errorMessage(err);
		}
	}
</script>

<svelte:head>
	<title>edumdns - {group.name}</title>
</svelte:head>

<!-- Group Detail Content -->
<div class="lg:w-3/4 w-full mx-auto px-4 sm:px-8 mb-10 md:mb-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-4">
		<h2 class="text-3xl font-bold text-sat-xl">
			{group.name}
		</h2>
		<button
			type="button"
			onclick={deleteGroup}
			class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md"
			title="Delete group"
			aria-label="Delete group"
		>
			<i class="fa-solid fa-trash"></i>
		</button>
	</div>
	<ErrorAlert message={deleteError} />

	<!-- Editable Group Settings -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">Group Settings</h3>
		<!-- ID -->
		<div class="flex flex-col mb-4">
			<span class="text-xs uppercase tracking-wide text-sat-m">ID</span>
			<span class="font-mono text-code"><code>{group.id}</code></span>
		</div>
		<form class="grid grid-cols-1 md:grid-cols-2 gap-4" onsubmit={saveSettings}>
			<!-- Name -->
			<div class="flex flex-col">
				<label for="name" class="text-xs uppercase tracking-wide text-sat-m">Name</label>
				<input
					id="name"
					name="name"
					type="text"
					placeholder="Group name"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					bind:value={editName}
				/>
				<p class="text-xs text-sat-m mt-1">Optional name for the group.</p>
			</div>

			<!-- Description -->
			<div class="flex flex-col md:col-span-2">
				<label for="description" class="text-xs uppercase tracking-wide text-sat-m"
					>Description</label
				>
				<textarea
					id="description"
					name="description"
					placeholder="Group description"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					rows="3"
					bind:value={editDescription}
				></textarea>
				<p class="text-xs text-sat-m mt-1">Optional description of this group.</p>
			</div>

			<!-- Actions -->
			<div class="md:col-span-2 flex items-center gap-2 pt-2">
				<button
					type="submit"
					class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium text-acc-cta transition-colors"
				>
					Save
				</button>
				<button
					type="button"
					onclick={resetSettings}
					class="inline-flex items-center rounded-md text-button bg-acc-l px-4 py-2 text-sm font-medium text-sat-l hover:bg-panes transition-colors"
				>
					Reset
				</button>
			</div>
			<div class="md:col-span-2">
				<ErrorAlert message={settingsError} />
				{#if settingsSaved}
					<div class="text-success mb-3">Group settings saved.</div>
				{/if}
			</div>
		</form>
	</div>
	<!-- Add Users to Group -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-semibold text-sat-l mb-4">Add users to this group</h3>

		<form id="add-users-form" class="space-y-4" onsubmit={addUsers}>
			<!-- Search box -->
			<div class="relative">
				<label for="user-search" class="sr-only">Search users</label>
				<input
					id="user-search"
					name="q"
					type="text"
					placeholder="Search users by name or email..."
					class="w-full rounded-md border border-base bg-panes px-3 py-2 text-sat-l"
					bind:value={userSearch}
				/>
				<p class="text-xs text-sat-m mt-1">Type to search. Select users below to add.</p>
			</div>

			<!-- Dropdown-like results list -->
			<div class="relative">
				<div
					id="user-search-results"
					class="max-h-64 overflow-auto rounded-md border border-base bg-panes"
					aria-live="polite"
				>
					{#if !userSearched}
						<div class="px-3 py-2 text-sat-m">Start typing to search for users…</div>
					{:else if userSearchError}
						<div class="px-3 py-2 text-error">{userSearchError}</div>
					{:else if userResults.length === 0}
						<div class="px-3 py-2 text-sat-m">No users found.</div>
					{:else}
						{#each userResults as user (user.id)}
							<div class="flex items-center gap-2 px-3 py-2 border-b border-base">
								<input
									type="checkbox"
									name="entity_ids[]"
									value={String(user.id)}
									class="shrink-0"
									checked={selectedUserIds.includes(user.id)}
									onchange={(e) => toggleUser(user.id, e.currentTarget.checked)}
								/>
								<div class="flex flex-col">
									<span class="text-sat-l font-medium">{user.name} {user.surname}</span>
									<span class="text-sat-m text-sm">{user.email}</span>
								</div>
							</div>
						{/each}
					{/if}
				</div>
			</div>

			<!-- Submit -->
			<div class="flex justify-end gap-2">
				<button
					type="submit"
					class="inline-flex items-center gap-2 rounded-md bg-acc text-button px-3 py-2 text-sm text-sat-l font-medium hover:bg-muted/20 transition-colors"
					title="Add selected users"
					aria-label="Add selected users"
				>
					<i class="fa-solid fa-user-plus"></i>
					Add users
				</button>
			</div>
			<ErrorAlert message={addUsersError} />
		</form>
	</div>
	<div id="group-users" class="rounded-lg border border-base bg-cards p-6">
		<h3 class="text-2xl font-semibold text-sat-l mb-4">Users in this group</h3>
		{#if template.users.length > 0}
			<div class="overflow-x-auto rounded-lg">
				<table class="min-w-full divide-y divide-base">
					<thead class="bg-muted/10">
						<tr>
							<th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th>
							<th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th>
							<th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Email</th>
							<th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-base">
					{#each template.users as u (u.id)}
						<tr class="cursor-pointer rounded-lg bg-table transition-colors" onclick={(e) => handleRowClick(e, `/user/${u.id}`)}>
							<td class="px-4 py-3 font-mono text-sm text-sat-l"><a href="/user/{u.id}">{u.id}</a></td>
							<td class="px-4 py-3 text-sm text-sat-l">{u.name} {u.surname}</td>
							<td class="px-4 py-3 text-sm text-sat-l">{u.email}</td>
							<td class="px-4 py-3 text-sm text-sat-l">
								<button
									type="button"
									onclick={() => removeUser(u.id)}
									class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
									title="Delete user from group"
								>
									<i class="fa-solid fa-trash"></i>
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
				</table>
			</div>
		{:else}
			<div class="p-4 text-muted-foreground">No users in this group.</div>
		{/if}
		<ErrorAlert message={removeUserError} class="mt-3" />
	</div>
</div>
