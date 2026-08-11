import { get } from '$lib/api';
import type { PacketUpdatePayloadTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const template = await get<PacketUpdatePayloadTemplate>(`/packet/${params.id}/update-payload`);
	return { template };
};
