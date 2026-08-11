import { g as get } from "../../../../chunks/api.js";
const load = async ({ url }) => {
  const sp = url.searchParams;
  const template = await get("/device", {
    page: sp.get("page"),
    id: sp.get("id"),
    probe_id: sp.get("probe_id"),
    mac: sp.get("mac"),
    ip: sp.get("ip"),
    port: sp.get("port"),
    name: sp.get("name"),
    published: sp.get("published"),
    proxy: sp.get("proxy"),
    exclusive: sp.get("exclusive")
  });
  return { template };
};
export {
  load
};
