// @ts-nocheck
import { get } from '$lib/api';
import type { DeviceTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ url }: Parameters<PageLoad>[0]) => {
	const sp = url.searchParams;
	const template = await get<DeviceTemplate>('/device', {
		page: sp.get('page'),
		id: sp.get('id'),
		probe_id: sp.get('probe_id'),
		mac: sp.get('mac'),
		ip: sp.get('ip'),
		port: sp.get('port'),
		name: sp.get('name'),
		published: sp.get('published'),
		proxy: sp.get('proxy'),
		exclusive: sp.get('exclusive')
	});
	return { template };
};
