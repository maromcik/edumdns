<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { buildQuery, errorMessage, getAction, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import { hasPermission, type Permission } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const device = $derived(template.device);
	const permissions = $derived(template.permissions);

	function can(permission: Permission): boolean {
		return hasPermission(permissions, permission);
	}

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

	// ---------------------------------------------------------------------------
	// Header actions
	// ---------------------------------------------------------------------------
	const publish = () => runAction(() => getAction(`/device/${device.id}/publish`));
	const hide = () => runAction(() => getAction(`/device/${device.id}/hide`));

	async function deleteDevice() {
		actionError = null;
		try {
			await sendForm('DELETE', `/device/${device.id}/delete`);
			await goto('/device');
		} catch (err) {
			actionError = errorMessage(err);
		}
	}

	function craftPacket() {
		goto(
			`/packet/create${buildQuery({
				probe_id: device.probe_id,
				mac: device.mac,
				ip: device.ip,
				port: device.port
			})}`
		);
	}

	// ---------------------------------------------------------------------------
	// Device settings (POST device/update)
	// ---------------------------------------------------------------------------
	let settingsName = $state('');
	let settingsMac = $state('');
	let settingsIp = $state('');
	let settingsPort = $state('');
	let settingsDuration = $state('');
	let settingsInterval = $state('');
	let settingsAclPassword = $state('');
	let settingsAclSrcCidr = $state('');
	let settingsAclApHostnameRegex = $state('');
	let settingsProxy = $state(false);
	let settingsExclusive = $state(false);

	$effect.pre(() => {
		const d = data.template.device;
		settingsName = d.name ?? '';
		settingsMac = d.mac;
		settingsIp = d.ip;
		settingsPort = String(d.port);
		settingsDuration = String(d.duration);
		settingsInterval = String(d.interval);
		settingsAclPassword = d.acl_pwd_hash ?? '';
		settingsAclSrcCidr = d.acl_src_cidr ?? '';
		settingsAclApHostnameRegex = d.acl_ap_hostname_regex ?? '';
		settingsProxy = d.proxy;
		settingsExclusive = d.exclusive;
	});

	async function saveSettings(event: Event) {
		event.preventDefault();
		// Empty optionals must be sent as empty strings (Actix empty_string_is_none).
		await runAction(() =>
			sendForm('POST', '/device/update', {
				id: device.id,
				name: settingsName,
				mac: settingsMac,
				ip: settingsIp,
				port: settingsPort,
				duration: settingsDuration,
				interval: settingsInterval,
				acl_password: settingsAclPassword,
				acl_src_cidr: settingsAclSrcCidr,
				acl_ap_hostname_regex: settingsAclApHostnameRegex,
				proxy: settingsProxy,
				exclusive: settingsExclusive
			})
		);
	}

	function resetSettings() {
		const d = device;
		settingsName = d.name ?? '';
		settingsMac = d.mac;
		settingsIp = d.ip;
		settingsPort = String(d.port);
		settingsDuration = String(d.duration);
		settingsInterval = String(d.interval);
		settingsAclPassword = d.acl_pwd_hash ?? '';
		settingsAclSrcCidr = d.acl_src_cidr ?? '';
		settingsAclApHostnameRegex = d.acl_ap_hostname_regex ?? '';
		settingsProxy = d.proxy;
		settingsExclusive = d.exclusive;
	}

	// ---------------------------------------------------------------------------
	// Custom packet transmission request (POST device/{id}/transmit-custom)
	// ---------------------------------------------------------------------------
	let targetIp = $state('');
	let targetPort = $state('');
	let permanent = $state(false);

	async function transmitCustom() {
		await runAction(() =>
			sendForm('POST', `/device/${device.id}/transmit-custom`, {
				target_ip: targetIp,
				target_port: targetPort,
				permanent
			})
		);
	}

	const extendTransmitRequest = (requestId: number) =>
		runAction(() =>
			sendForm('POST', `/device/${device.id}/transmit-custom/${requestId}/extend`, {})
		);

	const deleteTransmitRequest = (requestId: number) =>
		runAction(() => sendForm('DELETE', `/device/${device.id}/transmit/${requestId}`));

	// ---------------------------------------------------------------------------
	// Packets table filters
	// ---------------------------------------------------------------------------
	const pageFilters = $derived({
		id: template.filters.id,
		src_mac: template.filters.src_mac,
		dst_mac: template.filters.dst_mac,
		src_addr: template.filters.src_addr,
		dst_addr: template.filters.dst_addr,
		src_port: template.filters.src_port,
		dst_port: template.filters.dst_port,
		payload_string: template.filters.payload_string
	});

	let filterId = $state('');
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
			`/device/${device.id}${buildQuery({
				id: filterId.trim(),
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
		await goto(`/device/${device.id}`);
	}

	function handleRowClick(event: MouseEvent, href: string) {
		const target = event.target as HTMLElement | null;
		if (target?.closest('a, button, input, textarea, select')) return;
		if (window.getSelection()?.toString()) return;
		goto(href);
	}

	const deletePacket = (packetId: number) =>
		runAction(() => sendForm('DELETE', `/packet/${packetId}/delete`));
</script>

<svelte:head>
	<title>edumdns - Device {device.name ?? device.id}</title>
</svelte:head>

<div class="2xl:w-5/6 w-full mx-auto px-4 sm:px-8">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<h1 class="text-4xl font-semibold text-sat-xl">
			Device {device.name !== null ? device.name : device.id}
		</h1>
	</div>
	<div class="flex items- gap-2 mb-6">
		<a
			href="/device"
			class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors"
		>
			←
		</a>
		<div class="flex items-center gap-2">
			<button
				onclick={() => goto(`/device/${device.id}/transmit`)}
				class="flex items-center justify-center w-10 h-10 bg-blue-400 hover:bg-blue-500 rounded-md text-button shadow-md"
				title="Open device transmit/discovery page"
			>
				<i class="fa-solid fa-rss"></i>
			</button>
			{#if can('Update')}
				{#if device.published}
					<!-- Hide -->
					<button
						onclick={hide}
						class="flex items-center justify-center w-10 h-10 bg-fuchsia-400 hover:bg-fuchsia-500 rounded-md text-button shadow-md"
						title="Unpublish (hide) device"
					>
						<i class="fa-solid fa-eye-slash"></i>
					</button>
				{:else}
					<!-- Publish -->
					<button
						onclick={publish}
						class="flex items-center justify-center w-10 h-10 bg-lime-500 hover:bg-lime-600 rounded-md text-button shadow-md"
						title="Publish device (available for public users)"
					>
						<i class="fa-solid fa-eye"></i>
					</button>
				{/if}
			{/if}

			{#if can('Delete')}
				<!-- Delete -->
				<button
					onclick={deleteDevice}
					class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md"
					title="Delete device"
				>
					<i class="fa-solid fa-trash"></i>
				</button>
			{/if}
			{#if can('Create')}
				<button
					onclick={craftPacket}
					class="flex items-center justify-center w-10 h-10 bg-acc hover:bg-acc-l rounded-md text-button shadow-md"
					title="Craft a new packet"
				>
					<i class="fa-solid fa-plus"></i>
				</button>
			{/if}
		</div>
	</div>

	<ErrorAlert message={actionError} />

	<!-- Device Card -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
			<!-- ID -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">ID</span>
				<span class="font-mono text-code"><code>{device.id}</code></span>
			</div>

			<!-- Probe ID -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Probe ID</span>
				<span class="font-mono">
					<a class="hover:underline" href="/probe/{device.probe_id}">{device.probe_id}</a>
				</span>
			</div>

			<!-- TIME -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Discovered At</span>
				<span class="text-sat-l">{device.discovered_at}</span>
			</div>
		</div>
	</div>

	<!-- Editable Device Settings -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">Device Settings</h3>
		<form
			id="device-update-form"
			onsubmit={saveSettings}
			class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"
		>
			<!-- Name -->
			<div class="flex flex-col">
				<label for="name" class="text-xs uppercase tracking-wide text-forms">Name</label>
				<input
					id="name"
					name="name"
					type="text"
					bind:value={settingsName}
					placeholder="Friendly name"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
				/>
				<p class="text-xs text-sat-m mt-1">Optional friendly name for the device.</p>
			</div>

			<!-- MAC -->
			<div class="flex flex-col">
				<label for="mac" class="text-xs uppercase tracking-wide text-forms">MAC</label>
				<input
					id="mac"
					name="mac"
					bind:value={settingsMac}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					required
				/>
			</div>

			<!-- IP -->
			<div class="flex flex-col">
				<label for="ip" class="text-xs uppercase tracking-wide text-forms">IP</label>
				<input
					id="ip"
					name="ip"
					bind:value={settingsIp}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					required
				/>
			</div>
			<!-- Port -->
			<div class="flex flex-col">
				<label for="port" class="text-xs uppercase tracking-wide text-forms">Port</label>
				<input
					id="port"
					name="port"
					type="number"
					min="1"
					max="65535"
					bind:value={settingsPort}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					required
				/>
			</div>

			<!-- Duration -->
			<div class="flex flex-col">
				<label for="duration" class="text-xs uppercase tracking-wide text-forms">Duration</label>
				<input
					id="duration"
					name="duration"
					type="number"
					min="0"
					step="1"
					bind:value={settingsDuration}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					required
				/>
				<p class="text-xs text-sat-m mt-1">Duration in seconds.</p>
			</div>

			<!-- Interval -->
			<div class="flex flex-col">
				<label for="interval" class="text-xs uppercase tracking-wide text-forms">Interval</label>
				<input
					id="interval"
					name="interval"
					type="number"
					min="0"
					step="1"
					bind:value={settingsInterval}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					required
				/>
				<p class="text-xs text-sat-m mt-1">Interval in milliseconds.</p>
			</div>

			<!-- Password -->
			<div class="flex flex-col">
				<label for="acl_password" class="text-xs uppercase tracking-wide text-forms">Password</label>
				<input
					id="acl_password"
					name="acl_password"
					bind:value={settingsAclPassword}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					placeholder="Secret"
				/>
				<p class="text-xs text-sat-m mt-1">
					Password clients must provide to initiate packet transmission
				</p>
			</div>

			<!-- Src CIDS -->
			<div class="flex flex-col">
				<label for="acl_src_cidr" class="text-xs uppercase tracking-wide text-forms"
					>SRC SUBNET</label
				>
				<input
					id="acl_src_cidr"
					name="acl_src_cidr"
					bind:value={settingsAclSrcCidr}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					placeholder="e.g., 192.168.1.0/24"
				/>
				<p class="text-xs text-sat-m mt-1">Client source IP subnet</p>
			</div>

			<!-- AP hostname regex -->
			<div class="flex flex-col">
				<label for="acl_ap_hostname_regex" class="text-xs uppercase tracking-wide text-forms"
					>AP Hostname REGEX</label
				>
				<input
					id="acl_ap_hostname_regex"
					name="acl_ap_hostname_regex"
					bind:value={settingsAclApHostnameRegex}
					placeholder="Regex"
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
				/>
				<p class="text-xs text-sat-m mt-1">
					Regex over the hostname of an AP a client is connected to
				</p>
			</div>
			<div class="flex flex-col">
				<!-- Use Proxy -->
				<label class="inline-flex items-center mb-2">
					<input
						type="checkbox"
						name="proxy"
						class="rounded border-gray-300 text-acc focus:ring-acc"
						bind:checked={settingsProxy}
					/>
					<span class="ml-2 text-sat-m">Use Proxy</span>
				</label>

				<!-- Exclusive Discovery -->
				<label class="inline-flex items-center">
					<input
						type="checkbox"
						name="exclusive"
						class="rounded border-gray-300 text-acc focus:ring-acc"
						bind:checked={settingsExclusive}
					/>
					<span class="ml-2 text-sat-m">Exclusive discovery</span>
				</label>
			</div>
		</form>
		{#if can('Update')}
			<!-- Actions -->
			<div class="md:col-span-2 flex items-center gap-2 pt-2">
				<button
					type="submit"
					onclick={saveSettings}
					class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors"
				>
					Save
				</button>
				<button
					type="reset"
					onclick={resetSettings}
					class="inline-flex items-center rounded-md bg-acc-l px-4 py-2 text-sm font-medium text-button transition-colors"
				>
					Reset
				</button>
			</div>
		{/if}
	</div>

	<!-- Request Packet Transmission -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-6">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">Request Packet Transmission</h3>

		<form class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			<!-- Target IP -->
			<div class="flex flex-col">
				<label for="target_ip" class="text-xs uppercase tracking-wide text-forms">Target IP</label>
				<input
					id="target_ip"
					name="target_ip"
					type="text"
					inputmode="numeric"
					placeholder="e.g., 8.8.8.8"
					bind:value={targetIp}
					required
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
				/>
				<p class="text-xs text-sat-m mt-1">Destination IPv4/IPv6 subnet.</p>
			</div>

			<!-- Target Port -->
			<div class="flex flex-col">
				<label for="target_port" class="text-xs uppercase tracking-wide text-forms"
					>Target Port</label
				>
				<input
					id="target_port"
					name="target_port"
					type="number"
					min="1"
					max="65535"
					placeholder="e.g., 53"
					bind:value={targetPort}
					required
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
				/>
				<p class="text-xs text-sat-m mt-1">Destination TCP/UDP port (1–65535).</p>
			</div>

			<div class="md:col-span-2 flex items-center gap-2">
				<input
					id="permanent"
					name="permanent"
					type="checkbox"
					class="h-4 w-4 rounded border-base bg-panes text-acc focus:ring-2 focus:ring-acc"
					bind:checked={permanent}
				/>
				<label for="permanent" class="text-sm text-sat-l">Permanent</label>
			</div>

			<!-- Actions -->
			<div class="md:col-span-2 flex items-center gap-2">
				<button
					type="button"
					onclick={transmitCustom}
					class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors"
				>
					Transmit
				</button>
			</div>
		</form>
	</div>

	<div class="rounded-lg border border-base bg-cards p-6 mb-6">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">Packet Transmissions in progress</h3>

		<div class="overflow-x-auto">
			<table class="min-w-full divide-y divide-base">
				<thead class="bg-panes">
					<tr>
						<th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide"
							>User
						</th>
						<th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide"
							>Target IP
						</th>
						<th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide"
							>Target Port
						</th>
						<th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide"
							>Permanent
						</th>
						<th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide"
							>Valid Until</th
						>
						<th class="px-4 py-2 text-right text-xs font-medium text-sat-m uppercase tracking-wide"
							>Actions</th
						>
						<th class="px-4 py-2 text-right text-xs font-medium text-sat-m uppercase tracking-wide"
						></th>
					</tr>
				</thead>
				<tbody class="divide-y divide-base">
					{#if template.packet_transmit_requests.length > 0}
						{#each template.packet_transmit_requests as r (r.id)}
							<tr class="bg-table rounded-lg transition-colors">
								<td class="px-4 py-2 text-sat-l"
									><a href="/user/{r.user_id}">{r.user_id}</a></td
								>
								<td class="px-4 py-2 text-sat-l">{r.target_ip}</td>
								<td class="px-4 py-2 text-sat-l">{r.target_port}</td>
								<td class="px-4 py-2 text-sat-l">{r.permanent}</td>
								<td class="px-4 py-2 text-sat-l">{r.until}</td>
								<td class="px-4 py-2">
									<div class="flex justify-end">
										<button
											type="button"
											class="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm  transition-colors"
											title="Extend Discovery"
											onclick={() => extendTransmitRequest(r.id)}
										>
											<i class="fa-solid fa-arrows-rotate text-blue-400 hover:text-blue-500"></i>
										</button>
									</div>
								</td>
								<td class="px-4 py-2">
									<div class="flex justify-end">
										<button
											type="button"
											class="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm  transition-colors"
											title="Delete"
											onclick={() => deleteTransmitRequest(r.id)}
										>
											<i class="fa fa-trash text-red-400 hover:text-red-500"></i>
										</button>
									</div>
								</td>
							</tr>
						{/each}
					{:else}
						<tr>
							<td colspan="6" class="px-4 py-6 text-center text-sat-m"
								>No packet transmissions.</td
							>
						</tr>
					{/if}
				</tbody>
			</table>
		</div>
	</div>

	<!-- Packets Table -->
	<div class="overflow-x-auto rounded-lg border border-base bg-cards">
		<div class="flex flex-col justify-center items-center py-4">
			<h2 class="text-3xl font-medium text-sat-xl">Packets</h2>
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
						Src MAC
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Dst MAC
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Src Addr
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Dst Addr
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Src Port
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Dst Port
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Payload
					</th>
					<th
						scope="col"
						class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground"
					>
						Captured At
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
			<tbody class="divide-y divide-base">
				{#each template.packets as packet (packet.id)}
					<tr
						class="cursor-pointer rounded-lg bg-table transition-colors"
						onclick={(e) => handleRowClick(e, `/packet/${packet.id}`)}
					>
						<td class="px-4 py-3 font-mono text-sm text-sat-l">
							<a href="/packet/{packet.id}" class="text-primary hover:underline">
								{packet.id}
							</a>
						</td>
						<td class="px-4 py-3 text-sm text-sat-l">{packet.src_mac}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{packet.dst_mac}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{packet.src_addr}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{packet.dst_addr}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{packet.src_port}</td>
						<td class="px-4 py-3 text-sm text-sat-l">{packet.dst_port}</td>
						<td class="px-4 py-3 text-sm text-sat-l"
							><span class="font-mono">{(packet.payload_string ?? '').slice(0, 100)}</span></td
						>
						<td class="px-4 py-3 text-sm text-sat-l"
							><span class="font-mono">{packet.captured_at}</span></td
						>
						{#if can('Delete')}
							<td class="px-4 py-3 text-sm text-sat-l">
								<button
									onclick={() => deletePacket(packet.id)}
									class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
									title="Delete Packet"
								>
									<i class="fa-solid fa-trash"></i>
								</button>
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table>

		{#if template.packets.length === 0}
			<div class="p-6 text-center text-muted-foreground">No packets found for this device.</div>
		{/if}
	</div>

	<Pagination
		pageInfo={template.page_info}
		basePath="/device/{device.id}"
		filters={pageFilters}
	/>
</div>
