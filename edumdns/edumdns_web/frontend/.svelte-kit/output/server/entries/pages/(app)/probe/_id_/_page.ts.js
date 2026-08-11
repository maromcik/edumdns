import { g as get } from "../../../../../chunks/api.js";
const load = async ({ params, url }) => {
  const sp = url.searchParams;
  const template = await get(`/probe/${params.id}`, {
    page: sp.get("page"),
    id: sp.get("id"),
    name: sp.get("name"),
    mac: sp.get("mac"),
    ip: sp.get("ip"),
    port: sp.get("port"),
    published: sp.get("published"),
    exclusive: sp.get("exclusive"),
    proxy: sp.get("proxy")
  });
  return { template };
};
export {
  load
};
