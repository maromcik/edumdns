import { g as get } from "../../../../chunks/api.js";
const load = async ({ url }) => {
  const sp = url.searchParams;
  const template = await get("/group", {
    page: sp.get("page"),
    name: sp.get("name"),
    description: sp.get("description")
  });
  return { template };
};
export {
  load
};
