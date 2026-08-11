<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { buildQuery, errorMessage, getAction, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import { hasPermission, type Permission } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const probe = $derived(template.probe);
	const permissions = $derived(template.permissions);
	const isAdmin = $derived(template.user.user.admin);

	function can(permission: Permission): boolean {
		return hasPermission(permissions, permission);
	}

	// ---------------------------------------------------------------------------
	// Live probe status (WebSocket), mirrors the old detail/page.html script. The
	// server pushes "true"/"false" liveness pings and string notifications; we
	// only need the liveness for the status dot.
	// ---------------------------------------------------------------------------
	let alive = $state<boolean | null>(null);

	$effect(() => {
		const probeId = data.template.probe.id;
		let ws: WebSocket | null = null;
		let retryTimer: ReturnType<typeof setTimeout> | undefined;
		let disposed = false;

		function connect() {
			if (disposed) return;
			const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
			const socket = new WebSocket(`${proto}://${window.location.host}/api/probe/${probeId}/ws`);
			ws = socket;
			socket.onmessage = (event: MessageEvent) => {
				if (event.data === 'true') alive = true;
				else if (event.data === 'false') alive = false;
			};
			socket.onclose = () => {
				if (!disposed) retryTimer = setTimeout(connect, 2000);
			};
			socket.onerror = () => socket.close();
		}
		connect();

		return () => {
			disposed = true;
			if (retryTimer) clearTimeout(retryTimer);
			if (ws) {
				ws.onclose = null;
				ws.close();
			}
		};
	});

	// ---------------------------------------------------------------------------
	// Shared mutation plumbing
	// ---------------------------------------------------------------------------
	let actionError = $state<string | null>(null);

	async function runAction(fn: () => Promise<unknown>) {
		actionError = null;
		try {
			await fn();
			await invalidateAll();
		} catch (err) {
			actionError = errorMessage(err);
		}
	}

	const reconnect = () => runAction(() => getAction(`/probe/${probe.id}/reconnect`));
	const adopt = () => runAction(() => getAction(`/probe/${probe.id}/adopt`));
	const forget = () => runAction(() => getAction(`/probe/${probe.id}/forget`));

	async function deleteProbe() {
		if (!confirm('Delete this probe? All devices and related packets will be removed.')) return;
		actionError = null;
		try {
			await sendForm('DELETE', `/probe/${probe.id}/delete`);
			await goto('/probe');
		} catch (err) {
			actionError = errorMessage(err);
		}
	}

	// ---------------------------------------------------------------------------
	// Probe settings (name + pre-shared key)
	// ---------------------------------------------------------------------------
	let settingsName = $state('');
	let settingsPsk = $state('');

	$effect.pre(() => {
		settingsName = data.template.probe.name ?? '';
		settingsPsk = data.template.probe.pre_shared_key ?? '';
	});

	async function saveSettings(event: SubmitEvent) {
		event.preventDefault();
		// Empty optionals must be sent as empty strings (Actix empty_string_is_none).
		await runAction(() =>
			sendForm('POST', '/probe/update', {
				id: probe.id,
				name: settingsName,
				pre_shared_key: settingsPsk
			})
		);
	}

	function resetSettings() {
		settingsName = probe.name ?? '';
		settingsPsk = probe.pre_shared_key ?? '';
	}

	// ---------------------------------------------------------------------------
	// Owner editing (admin only)
	// ---------------------------------------------------------------------------
	let editingOwner = $state(false);
	let ownerInput = $state('');

	function startEditOwner() {
		ownerInput = probe.owner_id != null ? String(probe.owner_id) : '';
		editingOwner = true;
	}

	async function saveOwner() {
		// Empty string clears the owner (backend treats "" as None).
		await runAction(() =>
			sendForm('POST', '/probe/update-owner', { id: probe.id, owner_id: ownerInput.trim() })
		);
		editingOwner = false;
	}

	// ---------------------------------------------------------------------------
	// Permission matrix (admin only)
	// ---------------------------------------------------------------------------
	const canModifyConfig = $derived(hasPermission(permissions, 'ModifyConfig') || isAdmin);

	async function togglePermission(groupId: number, permission: Permission, value: boolean) {
		await runAction(() =>
			sendForm('POST', `/probe/${probe.id}/permission/toggle`, {
				group_id: groupId,
				permission,
				value
			})
		);
	}

	// ---------------------------------------------------------------------------
	// Capture configs
	// ---------------------------------------------------------------------------
	interface ConfigEdit {
		id: number;
		interfaceValue: string;
		filterValue: string;
	}

	let cfgEdits = $state<ConfigEdit[]>([]);

	$effect.pre(() => {
		cfgEdits = data.template.configs.map((c) => ({
			id: c.id,
			interfaceValue: c.interface,
			filterValue: c.filter ?? ''
		}));
	});

	let newCfgInterface = $state('');
	let newCfgFilter = $state('');

	async function saveConfig(cfg: ConfigEdit) {
		await runAction(() =>
			sendForm('PUT', `/probe/${probe.id}/config/${cfg.id}`, {
				interface: cfg.interfaceValue,
				filter: cfg.filterValue
			})
		);
	}

	const deleteConfig = (configId: number) =>
		runAction(() => sendForm('DELETE', `/probe/${probe.id}/config/${configId}`));

	async function createConfig(event: SubmitEvent) {
		event.preventDefault();
		await runAction(() =>
			sendForm('POST', `/probe/${probe.id}/config`, {
				interface: newCfgInterface,
				filter: newCfgFilter
			})
		);
		newCfgInterface = '';
		newCfgFilter = '';
	}

	// ---------------------------------------------------------------------------
	// Device table filters
	// ---------------------------------------------------------------------------
	let filterId = $state('');
	let filterName = $state('');
	let filterMac = $state('');
	let filterIp = $state('');
	let filterPort = $state('');
	let filterPublished = $state('');
	let filterExclusive = $state('');
	let filterProxy = $state('');

	function boolFilter(value: boolean | null | undefined): string {
		return value === true ? 'true' : value === false ? 'false' : '';
	}

	$effect.pre(() => {
		const f = data.template.filters;
		filterId = f.id != null ? String(f.id) : '';
		filterName = f.name ?? '';
		filterMac = f.mac ?? '';
		filterIp = f.ip ?? '';
		filterPort = f.port != null ? String(f.port) : '';
		filterPublished = boolFilter(f.published);
		filterExclusive = boolFilter(f.exclusive);
		filterProxy = boolFilter(f.proxy);
	});

	async function runSearch() {
		await goto(
			`/probe/${probe.id}${buildQuery({
				id: filterId.trim(),
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
		await goto(`/probe/${probe.id}`);
	}

	const pageFilters = $derived({
		id: template.filters.id,
		name: template.filters.name,
		mac: template.filters.mac,
		ip: template.filters.ip,
		port: template.filters.port,
		published: template.filters.published,
		exclusive: template.filters.exclusive,
		proxy: template.filters.proxy
	});

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	const deleteDevice = (deviceId: number) =>
		runAction(() =>
			sendForm(
				'DELETE',
				`/device/${deviceId}/delete?return_url=${encodeURIComponent(`/probe/${probe.id}`)}`
			)
		);
</script>

<svelte:head>
	<title>edumdns - Probe {probe.name ?? probe.id}</title>
</svelte:head>

<div class="2xl:w-5/6 w-full mx-auto px-4 sm:px-8">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<h1 class="text-4xl font-semibold text-sat-xl flex items-center gap-2">
			<span
				class="inline-block w-3 h-3 rounded-full"
				class:bg-gray-400={alive === null}
				class:bg-green-500={alive === true}
				class:bg-red-500={alive === false}
			></span>
			Probe
			{#if probe.name === null}{probe.id.slice(0, 13)}...{:else}{probe.name}{/if}
		</h1>
	</div>

	<div class="flex items-center gap-2 mb-6">
		<div class="flex items-center gap-2">
			<a
				href="/probe"
				class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors"
			>
				←
			</a>
			{#if can('Reconnect')}
				<button
					class="bg-yellow-400 hover:bg-yellow-500 flex items-center justify-center w-10 h-10  rounded-md text-button shadow-md"
					title="Reconnect probe"
					onclick={reconnect}
				>
					<i class="fa-solid fa-rotate-right"></i>
				</button>
			{/if}
			{#if probe.adopted && can('Forget')}
				<button
					class="bg-purple-400 hover:bg-purple-500 items-center justify-center w-10 h-10  rounded-md text-button shadow-md"
					title="Stop (forget) probe"
					onclick={forget}
				>
					<i class="fa-solid fa-stop"></i>
				</button>
			{/if}
			{#if !probe.adopted && can('Adopt')}
				<button
					class="bg-green-400 hover:bg-green-500 items-center justify-center w-10 h-10  rounded-md text-button shadow-md"
					title="Resume (adopt) probe"
					onclick={adopt}
				>
					<i class="fa-solid fa-play"></i>
				</button>
			{/if}
			{#if can('Delete')}
				<button
					class="bg-red-600 hover:bg-red-700 items-center justify-center w-10 h-10  rounded-md text-button shadow-md"
					title="Permanently delete probe"
					onclick={deleteProbe}
				>
					<i class="fa-solid fa-trash"></i>
				</button>
			{/if}
			{#if can('Create')}
				<button
					class="bg-acc hover:bg-acc-xl items-center justify-center w-10 h-10  rounded-md text-button shadow-md"
					title="Add a new device"
					onclick={() => goto(`/device/create/${probe.id}`)}
				>
					<i class="fa-solid fa-plus"></i>
				</button>
			{/if}
		</div>
	</div>

	<ErrorAlert message={actionError} />

	<!-- Probe Card -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
			<!-- ID -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">ID</span>
				<span class="font-mono text-code"><code>{probe.id}</code></span>
			</div>

			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Owner</span>
				<span class="font-mono text-code flex items-center gap-2">
					{#if probe.owner_id === null}
						<span class="text-muted-foreground text-sat-m">—</span>
					{:else}
						<a href="/user/{probe.owner_id}">{probe.owner_id}</a>
					{/if}
					{#if isAdmin}
						{#if editingOwner}
							<input
								type="number"
								class="rounded-md border border-base px-2 py-1 text-sm w-28"
								bind:value={ownerInput}
								placeholder="User ID"
							/>
							<button
								type="button"
								class="text-xs text-acc hover:text-acc-xl"
								title="Save owner"
								onclick={saveOwner}
							>
								<i class="fa-solid fa-check"></i>
							</button>
							<button
								type="button"
								class="text-xs text-acc hover:text-acc-xl"
								title="Cancel"
								onclick={() => (editingOwner = false)}
							>
								<i class="fa-solid fa-xmark"></i>
							</button>
						{:else}
							<button
								class="text-xs text-acc hover:text-acc-xl"
								title="Edit owner"
								type="button"
								onclick={startEditOwner}
							>
								<i class="fa-solid fa-pen"></i>
							</button>
						{/if}
					{/if}
				</span>
			</div>

			<!-- MAC -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">MAC</span>
				<span class="font-mono text-code"><code>{probe.mac}</code></span>
			</div>

			<!-- IP -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">IP</span>
				<span class="font-mono text-code"><code>{probe.ip}</code></span>
			</div>

			<!-- TIME -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">First connected at</span>
				<span class="text-sat-l">{probe.first_connected_at}</span>
			</div>

			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Last connected at</span>
				<span class="text-sat-l">{probe.last_connected_at}</span>
			</div>

			<!-- Adopted -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Adopted</span>
				<span class="font-mono text-sat-xl">
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
				</span>
			</div>
		</div>
	</div>

	<!-- Make these fields editable -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">Probe Settings</h3>
		<form class="grid grid-cols-1 md:grid-cols-2 gap-4" onsubmit={saveSettings}>
			<!-- Name -->
			<div class="flex flex-col">
				<label for="name" class="text-xs uppercase tracking-wide text-sat-m">Name</label>
				<input
					id="name"
					name="name"
					type="text"
					bind:value={settingsName}
					placeholder="Friendly name"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
				/>
				<p class="text-xs text-sat-m mt-1">Optional friendly name for the probe.</p>
			</div>

			<!-- pre_shared_key -->
			<div class="flex flex-col">
				<label for="pre_shared_key" class="text-xs uppercase tracking-wide text-sat-m"
					>Pre-Shared Secret Key</label
				>
				<input
					id="pre_shared_key"
					name="pre_shared_key"
					type="text"
					bind:value={settingsPsk}
					placeholder="Optional pre-shared key"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
				/>
				<p class="text-xs text-sat-m mt-1">
					Optional Pre-Shared Key for increased security (probe traffic is encrypted nonetheless).
				</p>
			</div>

			{#if can('Update')}
				<!-- Actions -->
				<div class="md:col-span-2 flex items-center gap-2 pt-2">
					<button
						type="submit"
						class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium transition-colors"
					>
						Save
					</button>
					<button
						type="button"
						class="inline-flex items-center rounded-md text-button bg-acc-l px-4 py-2 text-sm font-medium transition-colors"
						onclick={resetSettings}
					>
						Reset
					</button>
				</div>
			{/if}
		</form>
	</div>

	<!-- Permissions Table -->
	{#if isAdmin}
		<div class="overflow-x-auto rounded-lg border border-base bg-cards mb-8">
			<div class="flex flex-col justify-center items-center py-4">
				<h2 class="text-3xl font-medium text-sat-xl">Permissions</h2>
			</div>
			<div class="overflow-x-auto rounded-lg">
				<table class="w-full divide-y divide-base">
					<thead class="bg-muted/10">
						<tr>
							<th
								scope="col"
								class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Group
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Full
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Read
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Adopt
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Forget
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Reconnect
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								ModifyConfig
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Delete
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Update
							</th>
							<th
								scope="col"
								class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
							>
								Create
							</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-base">
						{#each template.permission_matrix as [perms, group] (group.id)}
							<tr class="bg-table rounded-lg transition-colors">
								<td class="px-4 py-3 text-sm text-sat-l">
									<a href="/group/{group.id}">{group.name}</a>
								</td>
								{#each perms as [perm, checked] (perm)}
									<td class="px-4 py-3 text-sm text-sat-l text-center">
										<input
											type="checkbox"
											class="h-4 w-4 rounded border-base text-acc focus:ring-acc"
											{checked}
											disabled={!canModifyConfig || perm === 'Full' || perm === 'Read'}
											aria-label="Toggle permission"
											onchange={(e) => togglePermission(group.id, perm, e.currentTarget.checked)}
										/>
									</td>
								{/each}
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</div>
	{/if}

	<!-- Probe Configs Table -->
	<div class="overflow-x-auto rounded-lg border border-base bg-cards mt-8 mb-8">
		<div class="flex flex-col justify-center items-center py-4">
			<h2 class="text-3xl font-medium text-sat-xl">Capture Configs</h2>
		</div>

		<table class="min-w-full divide-y divide-base">
			<thead class="bg-muted/10">
				<tr>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Interface
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Filter
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-right text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Actions
					</th>
				</tr>
			</thead>
			<tbody class="divide-y divide-base">
				{#each cfgEdits as cfg (cfg.id)}
					<tr class="bg-table rounded-lg transition-colors">
						<td class="px-4 py-3 text-sm text-code">
							<input
								type="text"
								name="interface"
								bind:value={cfg.interfaceValue}
								class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm"
								required
							/>
						</td>
						<td class="px-4 py-3 text-sm text-code">
							<input
								type="text"
								name="filter"
								bind:value={cfg.filterValue}
								class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm"
								placeholder="optional"
							/>
						</td>
						<td class="px-4 py-3 text-right">
							{#if can('ModifyConfig')}
								<button
									type="submit"
									class="inline-flex items-center rounded-md bg-background px-3 py-1.5 text-m font-medium text-green-700 bg-green-50 hover:bg-green-200 text-primary hover:bg-muted/10 transition-colors"
									aria-label="Save config"
									title="Save"
									onclick={() => saveConfig(cfg)}
								>
									<i class="fa-solid fa-floppy-disk mr-1.5"></i>
								</button>
								<button
									class="ml-2 inline-flex items-center rounded-md bg-background px-3 py-1.5 text-m font-medium text-red-700 bg-red-50 hover:bg-red-200 transition-colors"
									type="button"
									aria-label="Delete config"
									title="Delete"
									onclick={() => deleteConfig(cfg.id)}
								>
									<i class="fa-solid fa-trash mr-1.5"></i>
								</button>
							{/if}
						</td>
					</tr>
				{/each}
				<!-- Add Config Row -->
				{#if can('ModifyConfig')}
					<tr class="hover:bg-muted/5 transition-colors">
						<td class="px-4 py-3 text-sm text-code">
							<input
								type="text"
								name="interface"
								class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm"
								form="cfg-create-form"
								placeholder="e.g. eth0"
								required
								bind:value={newCfgInterface}
							/>
						</td>

						<td class="px-4 py-3 text-sm text-code">
							<input
								type="text"
								name="filter"
								class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm"
								form="cfg-create-form"
								placeholder="optional, e.g. port 53"
								bind:value={newCfgFilter}
							/>
						</td>
						<td class="px-4 py-3 text-right">
							<form id="cfg-create-form" class="inline-flex" onsubmit={createConfig}>
								<button
									type="submit"
									class="inline-flex items-center rounded-md border border-base bg-background px-3 py-1.5 text-m font-medium text-acc hover:bg-muted/10 transition-colors"
									aria-label="Add config"
									title="Add config"
								>
									<i class="fa-solid fa-plus mr-1.5"></i>
									Add config
								</button>
							</form>
						</td>
					</tr>
				{/if}
			</tbody>
		</table>

		{#if template.configs.length === 0}
			<div class="p-6 text-center text-muted-foreground">No probe configs found for this probe.</div>
		{/if}
	</div>

	<!-- Devices Table -->
	<div class="overflow-x-auto rounded-lg border border-base bg-cards mt-8">
		<div class="flex flex-col justify-center items-center py-4">
			<h2 class="text-3xl font-medium text-sat-xl">Devices</h2>
		</div>

		<table class="min-w-full divide-y divide-base">
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
						Name
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						MAC
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						IP
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
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
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
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
							onchange={runSearch}
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
							onchange={runSearch}
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
							onchange={runSearch}
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
						{#if can('Delete')}
							<td class="px-4 py-3 text-sm text-sat-l">
								<button
									class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
									title="Delete device"
									onclick={() => deleteDevice(device.id)}
								>
									<i class="fa-solid fa-trash"></i>
								</button>
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table>

		{#if template.devices.length === 0}
			<div class="p-6 text-center text-muted-foreground">No devices found for this probe.</div>
		{/if}
	</div>

	<Pagination
		pageInfo={template.page_info}
		basePath={`/probe/${probe.id}`}
		filters={pageFilters}
	/>
</div>
