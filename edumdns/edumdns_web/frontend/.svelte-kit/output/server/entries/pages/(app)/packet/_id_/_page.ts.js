import { g as get } from "../../../../../chunks/api.js";
const load = async ({ params }) => {
  const template = await get(`/packet/${params.id}`);
  return { template };
};
export {
  load
};
