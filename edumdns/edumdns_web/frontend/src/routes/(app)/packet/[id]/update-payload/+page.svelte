<script lang="ts">
	import { goto } from '$app/navigation';
	import type { DnsMessage, UpdatePacketPayloadForm } from '$lib/types';
	import DnsPacketBuilder from '../../DnsPacketBuilder.svelte';
	import { parseServerMessage, postOctalJson } from '../../dns-builder';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);

	// Preload the current DNS payload into builder rows (port of the edit
	// template's `preloadDnsMessage`, including the octal decoding).
	const initial = $derived(parseServerMessage(template.message) ?? undefined);

	async function submit(message: DnsMessage) {
		const body: UpdatePacketPayloadForm = { packet_id: template.id, message };
		await postOctalJson('/packet/update-payload', body);
		await goto(`/packet/${template.id}`);
	}
</script>

<svelte:head>
	<title>edumdns - Edit Packet Payload</title>
</svelte:head>

<DnsPacketBuilder
	title="Edit Packet"
	metadata={{ probeId: template.probe_id, mac: template.mac, ip: template.ip, port: template.port }}
	{initial}
	onSubmit={submit}
/>
