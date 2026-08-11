import { get } from '$lib/api';
import type { DeviceDetailTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params, url }) => {
	const sp = url.searchParams;
	const template = await get<DeviceDetailTemplate>(`/device/${params.id}`, {
		page: sp.get('page'),
		id: sp.get('id'),
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
