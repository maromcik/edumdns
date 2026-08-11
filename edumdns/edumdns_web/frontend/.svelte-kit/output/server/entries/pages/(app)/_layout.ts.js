import { g as get } from "../../../chunks/api.js";
const load = async () => {
  const { user } = await get("/");
  return { user };
};
export {
  load
};
