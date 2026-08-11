import { h as head, e as escape_html, a as attr } from "../../../chunks/index2.js";
import "../../../chunks/client2.js";
import "@sveltejs/kit/internal";
import "../../../chunks/exports.js";
import "../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../chunks/root.js";
import "../../../chunks/state.svelte.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let email = "";
    let password = "";
    let submitting = false;
    head("1x05zx6", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - login</title>`);
      });
    });
    $$renderer2.push(`<div id="login_box" class="w-full h-full flex justify-center items-center"><form class="bg-cards shadow-lg rounded-lg p-5 flex flex-col items-center max-w-full w-96 mx-4 md:w-96 sm:w-96 lg:w-96 xl:w-1/4"><h2 class="text-forms text-2xl mb-6">Login</h2> <div id="error-area" class="text-error mb-3">${escape_html("")}</div> <div class="w-full mb-6 flex flex-col gap-2.5"><input type="email" name="email" placeholder="Email" class="p-2.5 rounded"${attr("value", email)} required=""/> <input type="password" name="password" placeholder="Heslo" class="p-2.5 rounded"${attr("value", password)} required=""/></div> <button type="submit"${attr("disabled", submitting, true)} class="w-full bg-acc rounded-md p-3 text-button text-lg shadow-md">Login</button> <div class="flex items-center my-4 w-full"><div class="flex-grow border-t border-gray-300"></div> <span class="mx-2 text-gray-500 text-sm">OR</span> <div class="flex-grow border-t border-gray-300"></div></div> <button type="button" class="w-full flex items-center justify-center gap-2 bg-blue-700 rounded-md p-3 text-lg shadow-md text-white"><span>Login with</span> <img src="/static/images/muni-lg-white.png" alt="MUNI" class="h-10"/></button></form></div>`);
  });
}
export {
  _page as default
};
