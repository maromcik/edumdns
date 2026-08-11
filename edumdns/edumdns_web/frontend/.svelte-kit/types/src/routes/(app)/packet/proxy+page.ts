// @ts-nocheck
import { get } from '$lib/api';
import type { PacketTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ url }: Parameters<PageLoad>[0]) => {
	const sp = url.searchParams;
	const template = await get<PacketTemplate>('/packet', {
		page: sp.get('page'),
		id: sp.get('id'),
		probe_id: sp.get('probe_id'),
		src_mac: sp.get('src_mac'),
		dst_mac: sp.get('dst_mac'),
		src_addr: sp.get('src_addr'),
		dst_addr: sp.get('dst_addr'),
		src_port: sp.get('src_port'),
		dst_port: sp.get('dst_port'),
		payload_string: sp.get('payload_string')
	});
	return { template };
};
