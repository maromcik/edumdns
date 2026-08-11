<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { errorMessage, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import { hasPermission } from '$lib/types';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const packet = $derived(template.packet);

	const canUpdate = $derived(hasPermission(template.permissions, 'Update'));
	const canDelete = $derived(hasPermission(template.permissions, 'Delete'));

	let probeId = $state('');
	let srcMac = $state('');
	let dstMac = $state('');
	let srcAddr = $state('');
	let dstAddr = $state('');
	let srcPort = $state('');
	let dstPort = $state('');

	function syncFields() {
		const p = data.template.packet;
		probeId = p.probe_id;
		srcMac = p.src_mac;
		dstMac = p.dst_mac;
		srcAddr = p.src_addr;
		dstAddr = p.dst_addr;
		srcPort = String(p.src_port);
		dstPort = String(p.dst_port);
	}

	// Re-sync the form fields whenever fresh data arrives (navigation, invalidateAll).
	$effect.pre(syncFields);

	let metadataError = $state<string | null>(null);

	async function saveMetadata(event: SubmitEvent) {
		event.preventDefault();
		metadataError = null;
		try {
			await sendForm('POST', '/packet/update', {
				id: packet.id,
				probe_id: probeId,
				src_mac: srcMac,
				dst_mac: dstMac,
				src_addr: srcAddr,
				dst_addr: dstAddr,
				src_port: srcPort,
				dst_port: dstPort
			});
			await invalidateAll();
		} catch (err) {
			metadataError = errorMessage(err);
		}
	}

	let editingDevice = $state(false);
	let reassignDeviceId = $state<number | null>(null);
	let reassignError = $state<string | null>(null);

	async function submitReassign(event: SubmitEvent) {
		event.preventDefault();
		if (reassignDeviceId == null) return;
		reassignError = null;
		try {
			await sendForm('POST', '/packet/reassign', {
				packet_id: packet.id,
				device_id: reassignDeviceId
			});
			editingDevice = false;
			reassignDeviceId = null;
			await invalidateAll();
		} catch (err) {
			reassignError = errorMessage(err);
		}
	}

	let deleteError = $state<string | null>(null);

	async function deletePacket() {
		deleteError = null;
		try {
			await sendForm('DELETE', `/packet/${packet.id}/delete`);
			await goto('/packet');
		} catch (err) {
			deleteError = errorMessage(err);
		}
	}
</script>

<svelte:head>
	<title>edumdns - Packet {packet.id}</title>
</svelte:head>

<div class="2xl:w-5/6 w-full mx-auto px-4 sm:px-8">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<h1 class="text-4xl font-semibold text-sat-l">Packet Detail</h1>
	</div>

	<div class="flex items-center gap-2 mb-6">
		<a
			href="/packet"
			class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors"
		>
			←
		</a>
		{#if canDelete}
			<!-- Delete -->
			<button
				title="Delete packet"
				onclick={deletePacket}
				class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md"
			>
				<i class="fa-solid fa-trash"></i>
			</button>
		{/if}
		{#if canUpdate}
			<a
				href="/packet/{packet.id}/update-payload"
				class="flex items-center justify-center w-10 h-10 bg-acc hover:bg-acc-l rounded-md text-button shadow-md"
				title="Edit packet"
			>
				<i class="fa-solid fa-pencil"></i>
			</a>
		{/if}
	</div>
	<ErrorAlert message={deleteError} />

	<!-- Packet Card -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
			<!-- ID -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">ID</span>
				<span class="font-mono text-code"><code>{packet.id}</code></span>
			</div>
			<!-- Probe ID -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Probe ID</span>
				<span class="font-mono">
					<a class="hover:underline" href="/probe/{packet.probe_id}">{packet.probe_id}</a>
				</span>
			</div>
			<!-- Device ID -->
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Device</span>
				<span id="device-id-field" class="font-mono text-code flex items-center gap-2">
					{#if editingDevice}
						<form onsubmit={submitReassign} class="flex items-center gap-2">
							<input type="hidden" name="packet_id" value={packet.id} />
							<input
								type="number"
								name="device_id"
								bind:value={reassignDeviceId}
								class="rounded-md border border-base bg-panes px-2 py-1 w-24 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
								placeholder="ID"
							/>
							<button type="submit" title="Save" class="text-xs text-green-600 hover:text-green-800">
								<i class="fa-solid fa-check"></i>
							</button>
						</form>
					{:else}
						{#if template.device_id == null}
							<span class="text-muted-foreground text-sat-m">—</span>
						{:else}
							<a href="/device/{template.device_id}" id="device-id-link">{template.device_id}</a>
						{/if}
						{#if canUpdate}
							<button
								id="edit-device-id-btn"
								class="text-xs text-acc hover:text-acc-xl"
								title="Edit Device"
								type="button"
								onclick={() => (editingDevice = true)}
							>
								<i class="fa-solid fa-pen"></i>
							</button>
						{/if}
					{/if}
				</span>
			</div>
			<div class="flex flex-col">
				<span class="text-xs uppercase tracking-wide text-sat-m">Captured at</span>
				<span class="text-sat-l">{packet.captured_at ?? ''}</span>
			</div>
		</div>
		<ErrorAlert message={reassignError} />
	</div>

	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium mb-4 text-sat-l">Packet metadata</h3>
		<p class="text-xs text-sat-m mt-1">
			Change these settings may reassign the packet to a different device.
		</p>
		<form onsubmit={saveMetadata} class="gap-4">
			<input type="hidden" id="packet_id" name="id" value={packet.id} />

			<div class="flex flex-col">
				<label for="probe_id" class="text-xs uppercase tracking-wide text-forms">Probe ID</label>
				<input
					id="probe_id"
					name="probe_id"
					bind:value={probeId}
					class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					required
				/>
			</div>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<div class="flex flex-col">
					<label for="src_mac" class="text-xs uppercase tracking-wide text-forms mt-4">
						Source MAC
					</label>
					<input
						id="src_mac"
						name="src_mac"
						bind:value={srcMac}
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
						required
					/>
				</div>

				<div class="flex flex-col">
					<label for="src_mac" class="text-xs uppercase tracking-wide text-forms mt-4">
						Destination MAC
					</label>
					<input
						id="dst_mac"
						name="dst_mac"
						bind:value={dstMac}
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
						required
					/>
				</div>

				<div class="flex flex-col">
					<label for="src_addr" class="text-xs uppercase tracking-wide text-forms mt-4">
						Source Address
					</label>
					<input
						id="src_addr"
						name="src_addr"
						bind:value={srcAddr}
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
						required
					/>
				</div>

				<div class="flex flex-col">
					<label for="dst_addr" class="text-xs uppercase tracking-wide text-forms mt-4">
						Destination Address
					</label>
					<input
						id="dst_addr"
						name="dst_addr"
						bind:value={dstAddr}
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
						required
					/>
				</div>

				<div class="flex flex-col">
					<label for="src_port" class="text-xs uppercase tracking-wide text-forms mt-4">
						Source Port
					</label>
					<input
						id="src_port"
						name="src_port"
						bind:value={srcPort}
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
						required
					/>
				</div>

				<div class="flex flex-col">
					<label for="dst_port" class="text-xs uppercase tracking-wide text-forms mt-4">
						Destination Port
					</label>
					<input
						id="dst_port"
						name="dst_port"
						bind:value={dstPort}
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
						required
					/>
				</div>
			</div>
			{#if canUpdate}
				<!-- Actions -->
				<div class="md:col-span-2 flex items-center gap-2 pt-2">
					<button
						type="submit"
						class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors"
					>
						Save
					</button>
					<button
						type="button"
						onclick={syncFields}
						class="inline-flex items-center rounded-md bg-acc-l px-4 py-2 text-sm font-medium text-button transition-colors"
					>
						Reset
					</button>
				</div>
			{/if}
		</form>
		<ErrorAlert message={metadataError} />
	</div>

	<!-- Payload -->
	<div class="rounded-lg border border-base bg-cards p-6 mb-8">
		<h3 class="text-2xl font-medium text-sat-l">Payload</h3>
		{#if packet.payload && packet.payload.length > 0}
			<div class="rounded-lg overflow-x-auto">
				<pre><code>{packet.payload}</code></pre>
			</div>
		{:else}
			<div class="rounded-lg bg-panes text-sat-m">— No payload —</div>
		{/if}
	</div>
</div>
