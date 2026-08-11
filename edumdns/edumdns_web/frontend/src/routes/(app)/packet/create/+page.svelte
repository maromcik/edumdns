<script lang="ts">
	import { goto } from '$app/navigation';
	import type { CreatePacketForm, CreateResponse, DnsMessage } from '$lib/types';
	import DnsPacketBuilder from '../DnsPacketBuilder.svelte';
	import { postOctalJson } from '../dns-builder';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);

	async function submit(message: DnsMessage) {
		const body: CreatePacketForm = {
			probe_id: template.probe_id,
			src_mac: template.mac,
			src_addr: template.ip,
			dst_port: template.port,
			message
		};
		const res = await postOctalJson<CreateResponse>('/packet/create', body);
		await goto(`/packet/${res.id}`);
	}
</script>

<svelte:head>
	<title>edumdns - Create Packet</title>
</svelte:head>

<DnsPacketBuilder
	title="Craft Packet"
	metadata={{ probeId: template.probe_id, mac: template.mac, ip: template.ip, port: template.port }}
	onSubmit={submit}
/>
