import "clsx";
import "@sveltejs/kit/internal";
import "./exports.js";
import "./utils2.js";
import "@sveltejs/kit/internal/server";
import "./root.js";
import "./state.svelte.js";
const API_BASE = "/api";
class ApiError extends Error {
  generic;
  constructor(generic) {
    super(generic.description);
    this.name = "ApiError";
    this.generic = generic;
  }
}
function buildQuery(params) {
  if (!params) return "";
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === void 0 || value === "") continue;
    sp.set(key, String(value));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}
async function parseError(res) {
  const fallback = {
    code: res.status,
    status_code: res.statusText,
    description: res.statusText
  };
  try {
    const body = await res.json();
    return new ApiError({ ...fallback, ...body });
  } catch {
    return new ApiError(fallback);
  }
}
async function request(method, path, init = {}, query) {
  const res = await fetch(`${API_BASE}${path}${buildQuery(query)}`, {
    method,
    credentials: "same-origin",
    ...init
  });
  if (res.status === 401) {
    throw await parseError(res);
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return void 0;
  const text = await res.text();
  if (!text) return void 0;
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError({
      code: res.status,
      status_code: res.statusText,
      description: "The server returned an unexpected non-JSON response."
    });
  }
}
function get(path, query) {
  return request("GET", path, {}, query);
}
export {
  ApiError as A,
  buildQuery as b,
  get as g
};
