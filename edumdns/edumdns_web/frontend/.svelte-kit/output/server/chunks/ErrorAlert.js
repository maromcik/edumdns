import { b as attr_class, e as escape_html, s as stringify } from "./index2.js";
function ErrorAlert($$renderer, $$props) {
  let { message, class: className = "mb-3" } = $$props;
  if (message) {
    $$renderer.push("<!--[0-->");
    $$renderer.push(`<div id="error-area"${attr_class(`text-error ${stringify(className)}`)}>${escape_html(message)}</div>`);
  } else {
    $$renderer.push("<!--[-1-->");
  }
  $$renderer.push(`<!--]-->`);
}
export {
  ErrorAlert as E
};
