import { g as get } from "../../../../../../chunks/api.js";
const load = async ({ params }) => {
  const template = await get(`/packet/${params.id}/update-payload`);
  return { template };
};
export {
  load
};
