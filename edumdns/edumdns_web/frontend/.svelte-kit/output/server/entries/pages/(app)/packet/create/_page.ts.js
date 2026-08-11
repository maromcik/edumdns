import { g as get } from "../../../../../chunks/api.js";
const load = async ({ url }) => {
  const sp = url.searchParams;
  const template = await get("/packet/create", {
    probe_id: sp.get("probe_id"),
    mac: sp.get("mac"),
    ip: sp.get("ip"),
    port: sp.get("port")
  });
  return { template };
};
export {
  load
};
