<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { buildQuery, errorMessage, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import type { CreateResponse, Id } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);

	const pageFilters = $derived({
		email: template.filters.email,
		id: template.filters.id,
		name: template.filters.name,
		surname: template.filters.surname,
		admin: template.filters.admin,
		disabled: template.filters.disabled
	});

	let filterId = $state('');
	let filterEmail = $state('');
	let filterName = $state('');
	let filterSurname = $state('');
	let filterAdmin = $state('');
	let filterDisabled = $state('');

	// Re-sync the filter inputs whenever fresh data arrives (navigation, invalidateAll).
	$effect.pre(() => {
		const f = data.template.filters;
		filterId = f.id != null ? String(f.id) : '';
		filterEmail = f.email ?? '';
		filterName = f.name ?? '';
		filterSurname = f.surname ?? '';
		filterAdmin = f.admin === true ? 'true' : f.admin === false ? 'false' : '';
		filterDisabled = f.disabled === true ? 'true' : f.disabled === false ? 'false' : '';
	});

	async function runSearch() {
		await goto(
			`/user${buildQuery({
				id: filterId.trim(),
				email: filterEmail.trim(),
				name: filterName.trim(),
				surname: filterSurname.trim(),
				admin: filterAdmin,
				disabled: filterDisabled
			})}`
		);
	}

	async function runReset() {
		await goto('/user');
	}

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	let newEmail = $state('');
	let newName = $state('');
	let newSurname = $state('');
	let newPassword = $state('');
	let newConfirmPassword = $state('');
	let newAdmin = $state(false);
	let formError = $state<string | null>(null);

	async function createUser(event: SubmitEvent) {
		event.preventDefault();
		formError = null;
		try {
			const res = await sendForm<CreateResponse>('POST', '/user/create', {
				email: newEmail,
				name: newName,
				surname: newSurname,
				admin: newAdmin,
				password: newPassword,
				confirm_password: newConfirmPassword
			});
			await goto(`/user/${res.id}`);
		} catch (err) {
			formError = errorMessage(err);
		}
	}

	async function deleteUser(id: Id) {
		if (!confirm('Are you sure you want to delete this user?')) return;
		formError = null;
		try {
			await sendForm('DELETE', `/user/${id}`);
			await invalidateAll();
		} catch (err) {
			formError = errorMessage(err);
		}
	}
</script>

<svelte:head>
	<title>edumdns - Users</title>
</svelte:head>

{#if data.user.user.admin}
	<div class="lg:w-3/4 w-full mx-auto mb-10 md:mb-5">
		<!-- Header Section -->
		<div class="flex flex-col justify-center items-center py-6">
			<h2 class="text-4xl font-bold text-sat-xl">Users</h2>
		</div>

		<!-- New User -->
		<div class="rounded-lg border border-base bg-cards p-6 mb-6">
			<h3 class="text-2xl font-semibold text-sat-l mb-4">New User</h3>
			<form class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-3 gap-4" onsubmit={createUser}>
				<div class="flex flex-col">
					<label for="email" class="text-xs uppercase tracking-wide text-sat-l">Email</label>
					<input
						id="email"
						name="email"
						type="email"
						required
						class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc"
						placeholder="Enter email"
						bind:value={newEmail}
					/>
				</div>
				<div class="flex flex-col">
					<label for="name" class="text-xs uppercase tracking-wide text-sat-l">Name</label>
					<input
						id="name"
						name="name"
						type="text"
						required
						class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc"
						placeholder="Enter name"
						bind:value={newName}
					/>
				</div>
				<div class="flex flex-col">
					<label for="surname" class="text-xs uppercase tracking-wide text-sat-l">Surname</label>
					<input
						id="surname"
						name="surname"
						type="text"
						required
						class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc"
						placeholder="Enter surname"
						bind:value={newSurname}
					/>
				</div>
				<div class="flex flex-col">
					<label for="password" class="text-xs uppercase tracking-wide text-sat-l">Password</label>
					<input
						id="password"
						name="password"
						type="password"
						required
						class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc"
						placeholder="Enter password"
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
						required
						class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc"
						placeholder="Enter password again"
						bind:value={newConfirmPassword}
					/>
				</div>
				<div class="flex items-center mt-1">
					<input
						id="admin"
						name="admin"
						type="checkbox"
						value="true"
						class="h-4 w-4 rounded border-base text-forms-input text-acc focus:ring-2 focus:ring-acc"
						bind:checked={newAdmin}
					/>
					<label for="admin" class="ml-2 text-xs uppercase tracking-wide text-sat-l">Admin</label>
				</div>
				<div class="md:col-span-2">
					<button
						type="submit"
						class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium hover:bg-acc-xl transition-colors"
					>
						Create User
					</button>
				</div>
			</form>
			<ErrorAlert message={formError} class="mt-3" />
		</div>

		<div class="overflow-x-auto rounded-lg border border-base bg-cards">
			<table class="w-full divide-y divide-base">
				<thead class="bg-muted/10">
					<tr>
						<th
							scope="col"
							class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
						>
							ID
						</th>
						<th
							scope="col"
							class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
						>
							Email
						</th>
						<th
							scope="col"
							class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
						>
							Name
						</th>
						<th
							scope="col"
							class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
						>
							Surname
						</th>
						<th
							scope="col"
							class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
						>
							Admin
						</th>
						<th
							scope="col"
							class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
						>
							Disabled
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
								id="filter-email"
								bind:value={filterEmail}
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
								id="filter-surname"
								bind:value={filterSurname}
								onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), runSearch())}
								class="w-full rounded-md border border-base px-2 py-1 text-sm"
							/></td
						>
						<td class="px-4 py-2">
							<select
								id="filter-admin"
								class="w-full rounded-md border border-base px-2 py-1 text-sm"
								bind:value={filterAdmin}
								onchange={runSearch}
							>
								<option value="">All</option>
								<option value="true">Admin</option>
								<option value="false">Not Admin</option>
							</select>
						</td>
						<td class="px-4 py-2">
							<select
								id="filter-disabled"
								class="w-full rounded-md border border-base px-2 py-1 text-sm"
								bind:value={filterDisabled}
								onchange={runSearch}
							>
								<option value="">All</option>
								<option value="true">Disabled</option>
								<option value="false">Enabled</option>
							</select>
						</td>
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
					{#each template.users as user (user.id)}
						<tr
							class="cursor-pointer rounded-lg bg-table transition-colors"
							onclick={(e) => handleRowClick(e, `/user/${user.id}`)}
						>
							<td class="px-4 py-3 font-mono text-sm text-sat-l">
								<a href="/user/{user.id}" class="text-primary hover:underline">
									{user.id}
								</a>
							</td>
							<td class="px-4 py-3 text-sm text-sat-l">
								{user.email}
							</td>
							<td class="px-4 py-3 text-sm text-sat-l">
								{user.name}
							</td>
							<td class="px-4 py-3 text-sm text-sat-l">
								{user.surname}
							</td>
							<td class="px-4 py-3 text-sm">
								{#if user.admin}
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
								{#if !user.disabled}
									<span
										class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800"
										>No</span
									>
								{:else}
									<span
										class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800"
										>Yes</span
									>
								{/if}
							</td>
							<td class="px-4 py-3 text-sm text-sat-l">
								<button
									type="button"
									onclick={() => deleteUser(user.id)}
									class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
									title="Delete user"
								>
									<i class="fa-solid fa-trash"></i>
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>

			{#if template.users.length === 0}
				<div class="p-6 text-center text-muted-foreground">No users found.</div>
			{/if}
		</div>

		<Pagination pageInfo={template.page_info} basePath="/user" filters={pageFilters} />
	</div>
{:else}
	<ErrorAlert message="You must be an administrator to view users." />
{/if}
