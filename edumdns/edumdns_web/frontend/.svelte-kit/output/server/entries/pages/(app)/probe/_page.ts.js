import { g as get } from "../../../../chunks/api.js";
const load = async ({ url }) => {
  const sp = url.searchParams;
  const template = await get("/probe", {
    page: sp.get("page"),
    id: sp.get("id"),
    owner_id: sp.get("owner_id"),
    location_id: sp.get("location_id"),
    adopted: sp.get("adopted"),
    mac: sp.get("mac"),
    ip: sp.get("ip"),
    name: sp.get("name")
  });
  return { template };
};
export {
  load
};
