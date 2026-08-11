// @ts-nocheck
import { get } from '$lib/api';
import type { DeviceTransmitTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ params }: Parameters<PageLoad>[0]) => {
	const template = await get<DeviceTransmitTemplate>(`/device/${params.id}/transmit`);
	return { template };
};
