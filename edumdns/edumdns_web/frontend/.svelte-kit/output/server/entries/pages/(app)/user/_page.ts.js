import { g as get } from "../../../../chunks/api.js";
const load = async ({ url }) => {
  const sp = url.searchParams;
  const template = await get("/user", {
    page: sp.get("page"),
    email: sp.get("email"),
    id: sp.get("id"),
    name: sp.get("name"),
    surname: sp.get("surname"),
    admin: sp.get("admin"),
    disabled: sp.get("disabled")
  });
  return { template };
};
export {
  load
};
