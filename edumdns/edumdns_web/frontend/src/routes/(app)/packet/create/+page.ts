import { get } from '$lib/api';
import type { PacketCreateTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ url }) => {
	const sp = url.searchParams;
	const template = await get<PacketCreateTemplate>('/packet/create', {
		probe_id: sp.get('probe_id'),
		mac: sp.get('mac'),
		ip: sp.get('ip'),
		port: sp.get('port')
	});
	return { template };
};
