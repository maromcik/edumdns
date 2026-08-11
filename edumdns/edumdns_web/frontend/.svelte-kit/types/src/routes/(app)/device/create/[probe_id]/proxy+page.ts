// @ts-nocheck
import { get } from '$lib/api';
import type { DeviceCreateTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ params }: Parameters<PageLoad>[0]) => {
	const template = await get<DeviceCreateTemplate>(`/device/create/${params.probe_id}`);
	return { template };
};
