import { get } from '$lib/api';
import type { ProbeTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ url }) => {
	const sp = url.searchParams;
	const template = await get<ProbeTemplate>('/probe', {
		page: sp.get('page'),
		id: sp.get('id'),
		owner_id: sp.get('owner_id'),
		location_id: sp.get('location_id'),
		adopted: sp.get('adopted'),
		mac: sp.get('mac'),
		ip: sp.get('ip'),
		name: sp.get('name')
	});
	return { template };
};
