import { get } from '$lib/api';
import type { PacketDetailTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const template = await get<PacketDetailTemplate>(`/packet/${params.id}`);
	return { template };
};
