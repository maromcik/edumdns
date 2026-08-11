import { get } from '$lib/api';
import type { DeviceTransmitTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const template = await get<DeviceTransmitTemplate>(`/device/${params.id}/transmit`);
	return { template };
};
