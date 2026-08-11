import { get } from '$lib/api';
import type { DeviceCreateTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const template = await get<DeviceCreateTemplate>(`/device/create/${params.probe_id}`);
	return { template };
};
