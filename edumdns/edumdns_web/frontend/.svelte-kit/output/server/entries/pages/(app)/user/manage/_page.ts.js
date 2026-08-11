import { g as get } from "../../../../../chunks/api.js";
const load = async () => {
  const template = await get("/user/manage");
  return { template };
};
export {
  load
};
