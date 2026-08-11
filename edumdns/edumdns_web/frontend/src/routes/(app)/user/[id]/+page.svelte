<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { errorMessage, get, getAction, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import type { GenericError, Group, Id, UserDetailGroupsTemplate } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const targetUser = $derived(template.target_user.user);

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

	// ---- Delete user ----
	let deleteError = $state<string | null>(null);

	async function deleteUser() {
		if (!confirm('Are you sure you want to delete this user?')) return;
		deleteError = null;
		try {
			await sendForm('DELETE', `/user/${targetUser.id}`);
			await goto('/user');
		} catch (err) {
			deleteError = errorMessage(err);
		}
	}

	// ---- User settings form ----
	let editName = $state('');
	let editSurname = $state('');
	let editEmail = $state('');
	let editAdmin = $state(false);
	let editDisabled = $state(false);
	let settingsError = $state<string | null>(null);
	let settingsSaved = $state(false);

	$effect.pre(() => {
		const u = data.template.target_user.user;
		editName = u.name;
		editSurname = u.surname;
		editEmail = u.email;
		editAdmin = u.admin;
		editDisabled = u.disabled;
	});

	async function saveSettings(event: SubmitEvent) {
		event.preventDefault();
		settingsError = null;
		settingsSaved = false;
		try {
			await sendForm('POST', '/user/update', {
				id: targetUser.id,
				name: editName,
				surname: editSurname,
				email: editEmail,
				admin: editAdmin,
				disabled: editDisabled
			});
			settingsSaved = true;
			await invalidateAll();
		} catch (err) {
			settingsError = errorMessage(err);
		}
	}

	function resetSettings() {
		const u = template.target_user.user;
		editName = u.name;
		editSurname = u.surname;
		editEmail = u.email;
		editAdmin = u.admin;
		editDisabled = u.disabled;
	}

	// ---- Password form ----
	let newPassword = $state('');
	let confirmPassword = $state('');
	let passwordError = $state<string | null>(null);
	let passwordSaved = $state(false);

	async function savePassword(event: SubmitEvent) {
		event.preventDefault();
		passwordError = null;
		passwordSaved = false;
		try {
			await sendForm('POST', '/user/update-pwd', {
				id: targetUser.id,
				new_password: newPassword,
				confirm_password: confirmPassword
			});
			newPassword = '';
			confirmPassword = '';
			passwordSaved = true;
		} catch (err) {
			passwordError = errorMessage(err);
		}
	}

	// ---- Add to groups: debounced live search ----
	let groupSearch = $state('');
	let groupResults = $state<Group[]>([]);
	let groupSearched = $state(false);
	let groupSearchError = $state<string | null>(null);
	let selectedGroupIds = $state<Id[]>([]);
	let addGroupsError = $state<string | null>(null);
	let searchSeq = 0;

	async function runGroupSearch(q: string) {
		const seq = ++searchSeq;
		try {
			const res = await get<UserDetailGroupsTemplate>(`/user/${targetUser.id}/search`, { q });
			if (seq !== searchSeq) return;
			groupResults = res.groups;
			groupSearchError = null;
			groupSearched = true;
		} catch (err) {
			if (seq !== searchSeq) return;
			groupResults = [];
			groupSearchError = errorMessage(err);
			groupSearched = true;
		}
	}

	$effect(() => {
		const q = groupSearch.trim();
		if (!q) {
			searchSeq++;
			groupResults = [];
			groupSearchError = null;
			groupSearched = false;
			return;
		}
		const timer = setTimeout(() => void runGroupSearch(q), 300);
		return () => clearTimeout(timer);
	});

	function toggleGroup(id: Id, checked: boolean) {
		selectedGroupIds = checked
			? [...selectedGroupIds, id]
			: selectedGroupIds.filter((x) => x !== id);
	}

	async function addGroups(event: SubmitEvent) {
		event.preventDefault();
		addGroupsError = null;
		if (selectedGroupIds.length === 0) return;
		try {
			await postEntityIds(`/user/${targetUser.id}/groups/add`, selectedGroupIds);
			selectedGroupIds = [];
			groupSearch = '';
			await invalidateAll();
		} catch (err) {
			addGroupsError = errorMessage(err);
		}
	}

	// ---- Remove user from a group ----
	let removeGroupError = $state<string | null>(null);

	async function removeFromGroup(groupId: Id) {
		removeGroupError = null;
		try {
			await getAction(`/group/${groupId}/users/${targetUser.id}/delete`);
			await invalidateAll();
		} catch (err) {
			removeGroupError = errorMessage(err);
		}
	}
</script>

<svelte:head>
	<title>edumdns - {targetUser.name} {targetUser.surname}</title>
</svelte:head>

<!-- User Detail Content -->
<div class="lg:w-3/4 w-full mx-auto px-4 sm:px-8 mb-10 md:mb-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-4">
		<h2 class="text-3xl font-bold text-sat-xl">
			{targetUser.name}
			{targetUser.surname}
		</h2>
		<button
			type="button"
			onclick={deleteUser}
			class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md"
			title="Delete user"
			aria-label="Delete user"
		>
			<i class="fa-solid fa-trash"></i>
		</button>
	</div>
	<ErrorAlert message={deleteError} />

	<!-- Editable User Settings -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">User Settings</h3>
		<div class="flex flex-col mb-4">
			<span class="text-xs uppercase tracking-wide text-sat-m">ID</span>
			<span class="font-mono text-code"><code>{targetUser.id}</code></span>
		</div>
		<form class="grid grid-cols-1 md:grid-cols-2 gap-4" onsubmit={saveSettings}>
			<!-- Name -->
			<div class="flex flex-col">
				<label for="name" class="text-xs uppercase tracking-wide text-sat-l">Name</label>
				<input
					id="name"
					name="name"
					type="text"
					placeholder="First name"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					bind:value={editName}
				/>
			</div>

			<!-- Surname -->
			<div class="flex flex-col">
				<label for="surname" class="text-xs uppercase tracking-wide text-sat-l">Surname</label>
				<input
					id="surname"
					name="surname"
					type="text"
					placeholder="Surname"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					bind:value={editSurname}
				/>
			</div>

			<!-- Email -->
			<div class="flex flex-col md:col-span-2">
				<label for="email" class="text-xs uppercase tracking-wide text-sat-l">Email</label>
				<input
					id="email"
					name="email"
					type="email"
					placeholder="user@example.com"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					bind:value={editEmail}
				/>
			</div>

			<!-- Admin + Disabled -->
			<div class="flex items-center gap-4 md:col-span-2 mt-2">
				<label class="inline-flex items-center">
					<input
						type="checkbox"
						name="admin"
						value="true"
						class="rounded border-gray-300 text-acc focus:ring-acc"
						bind:checked={editAdmin}
					/>
					<span class="ml-2 text-sat-l">Admin</span>
				</label>

				<label class="inline-flex items-center">
					<input
						type="checkbox"
						name="disabled"
						value="true"
						class="rounded border-gray-300 text-acc focus:ring-acc"
						bind:checked={editDisabled}
					/>
					<span class="ml-2 text-sat-l">Disabled</span>
				</label>
			</div>

			<!-- Actions -->
			<div class="md:col-span-2 flex items-center gap-2 pt-2">
				<button
					type="submit"
					class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-acc-cta hover:bg-acc-xl transition-colors"
				>
					Save
				</button>
				<button
					type="button"
					onclick={resetSettings}
					class="inline-flex items-center rounded-md text-button px-4 py-2 text-sm font-medium bg-acc-l hover:bg-panes transition-colors"
				>
					Reset
				</button>
			</div>
			<div class="md:col-span-2">
				<ErrorAlert message={settingsError} />
				{#if settingsSaved}
					<div class="text-success mb-3">User settings saved.</div>
				{/if}
			</div>
		</form>
	</div>

	<!-- Editable User Password -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">User Password</h3>
		<form class="grid grid-cols-1 md:grid-cols-2 gap-4" onsubmit={savePassword}>
			<div class="flex flex-col">
				<label for="new_password" class="text-xs uppercase tracking-wide text-sat-l">Password</label
				>
				<input
					id="new_password"
					name="new_password"
					type="password"
					placeholder="Enter a new password"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					bind:value={newPassword}
				/>
			</div>

			<div class="flex flex-col">
				<label for="confirm_password" class="text-xs uppercase tracking-wide text-sat-l"
					>Confirm Password</label
				>
				<input
					id="confirm_password"
					name="confirm_password"
					type="password"
					placeholder="Enter the password again"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					bind:value={confirmPassword}
				/>
			</div>

			<!-- Actions -->
			<div class="md:col-span-2 flex items-center gap-2 pt-2">
				<button
					type="submit"
					class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium text-acc-cta hover:bg-acc-xl transition-colors"
				>
					Save
				</button>
				<button
					type="reset"
					class="inline-flex items-center rounded-md bg-acc-l px-4 py-2 text-sm font-medium text-button hover:bg-panes transition-colors"
				>
					Reset
				</button>
			</div>
			<div class="md:col-span-2">
				<ErrorAlert message={passwordError} />
				{#if passwordSaved}
					<div class="text-success mb-3">Password updated.</div>
				{/if}
			</div>
		</form>
	</div>

	<!-- Add User to Groups -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-semibold text-sat-l mb-4">Add this user to groups</h3>

		<form id="add-groups-form" class="space-y-4" onsubmit={addGroups}>
			<!-- Search box -->
			<div class="relative">
				<label for="group-search" class="sr-only">Search groups</label>
				<input
					id="group-search"
					name="q"
					type="text"
					placeholder="Search users by name or email..."
					class="w-full rounded-md border border-base bg-panes px-3 py-2 text-sat-l"
					bind:value={groupSearch}
				/>
				<p class="text-xs text-sat-m mt-1">Type to search. Select users below to add.</p>
			</div>

			<!-- Dropdown-like results list -->
			<div class="relative">
				<div
					id="group-search-results"
					class="max-h-64 overflow-auto rounded-md border border-base bg-panes"
					aria-live="polite"
				>
					{#if !groupSearched}
						<div class="px-3 py-2 text-sat-m">Start typing to search for groups…</div>
					{:else if groupSearchError}
						<div class="px-3 py-2 text-error">{groupSearchError}</div>
					{:else if groupResults.length === 0}
						<div class="px-3 py-2 text-sat-m">No groups found.</div>
					{:else}
						{#each groupResults as group (group.id)}
							<div class="flex items-center gap-2 px-3 py-2 border-b border-base">
								<input
									type="checkbox"
									name="entity_ids[]"
									value={String(group.id)}
									class="shrink-0"
									checked={selectedGroupIds.includes(group.id)}
									onchange={(e) => toggleGroup(group.id, e.currentTarget.checked)}
								/>
								<div class="flex flex-col">
									<span class="text-sat-l font-medium">{group.name}</span>
									<span class="text-sat-m text-sm">{group.description?.slice(0, 13) ?? ''}</span>
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
					class="inline-flex items-center gap-2 rounded-md bg-acc px-3 py-2 text-sm text-button font-medium hover:bg-muted/20 transition-colors"
					title="Add selected users"
					aria-label="Add selected users"
				>
					<i class="fa-solid fa-user-plus"></i>
					Add groups
				</button>
			</div>
			<ErrorAlert message={addGroupsError} />
		</form>
	</div>

	<div id="user-groups" class="rounded-lg border border-base bg-cards p-6">
		<h3 class="text-2xl font-semibold text-sat-l mb-4">Groups for this user</h3>

		{#if template.groups.length > 0}
			<div class="overflow-x-auto rounded-lg">
				<table class="min-w-full divide-y divide-base">
					<thead class="bg-muted/10">
						<tr>
							<th
								class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
								>ID</th
							>
							<th
								class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
								>Name</th
							>
							<th
								class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
								>Description</th
							>
							<th
								class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
								>Actions</th
							>
						</tr>
					</thead>
					<tbody class="divide-y divide-base">
						{#each template.groups as g (g.id)}
							<tr
								class="cursor-pointer rounded-lg bg-table transition-colors"
								onclick={(e) => handleRowClick(e, `/group/${g.id}`)}
							>
								<td class="px-4 py-3 font-mono text-sm text-sat-l"
									><a href="/group/{g.id}">{g.id}</a></td
								>
								<td class="px-4 py-3 text-sm text-sat-l">{g.name}</td>
								<td class="px-4 py-3 text-sm text-sat-l">{g.description?.slice(0, 13) ?? ''}</td>
								<td class="px-4 py-3 text-sm text-sat-l">
									<button
										type="button"
										onclick={() => removeFromGroup(g.id)}
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
			<div class="p-4 text-muted-foreground">User is in no groups.</div>
		{/if}
		<ErrorAlert message={removeGroupError} class="mt-3" />
	</div>
</div>
