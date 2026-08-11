import { g as get } from "../../../../../../chunks/api.js";
const load = async ({ params }) => {
  const template = await get(`/device/create/${params.probe_id}`);
  return { template };
};
export {
  load
};
