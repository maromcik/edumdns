import { g as get } from "../../../../../../chunks/api.js";
const load = async ({ params }) => {
  const template = await get(`/device/${params.id}/transmit`);
  return { template };
};
export {
  load
};
