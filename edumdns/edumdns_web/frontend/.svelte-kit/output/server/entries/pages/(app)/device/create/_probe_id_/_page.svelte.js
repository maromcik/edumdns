import { h as head, a as attr, d as derived } from "../../../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../../../chunks/exports.js";
import "../../../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../../../chunks/root.js";
import "../../../../../../chunks/state.svelte.js";
import { E as ErrorAlert } from "../../../../../../chunks/ErrorAlert.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    let name = "";
    let mac = "";
    let ip = "";
    let port = "";
    let createError = null;
    head("i7bdry", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Add a New Device</title>`);
      });
    });
    $$renderer2.push(`<div class="container mx-auto p-6 max-w-7xl"><form class="bg-cards shadow-md rounded px-8 pt-6 pb-8 mb-4"><h2 class="block text-forms text-xl font-bold mb-2 text-center">Add a New Device</h2> <input type="hidden" id="probe_id" name="probe_id"${attr("value", template().probe_id)}/> <div class="flex flex-col mb-4"><label for="name" class="text-xs uppercase tracking-wide text-forms">Name</label> <input id="name" name="name" type="text" placeholder="Friendly name"${attr("value", name)} class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-forms mt-1">Optional friendly name for the device.</p></div> <div class="flex flex-col mb-4"><label for="mac" class="text-xs uppercase tracking-wide text-forms">MAC Address</label> <input id="mac" name="mac" type="text" placeholder="AA:BB:CC:DD:EE:FF" pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"${attr("value", mac)} class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc" required=""/> <p class="text-xs text-forms mt-1">Enter the device MAC address in standard format.</p></div> <div class="flex flex-col mb-4"><label for="ip" class="text-xs uppercase tracking-wide text-forms">IP Address</label> <input id="ip" name="ip" type="text" placeholder="192.168.1.100/24"${attr("value", ip)} class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc" required=""/> <p class="text-xs text-forms mt-1">Use CIDR notation (e.g. <code>192.168.1.100/24</code>).</p></div> <div class="flex flex-col mb-6"><label for="port" class="text-xs uppercase tracking-wide text-forms">Port</label> <input id="port" name="port" type="number" min="1" max="65535"${attr("value", port)} class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> `);
    ErrorAlert($$renderer2, { message: createError });
    $$renderer2.push(`<!----> <div class="flex justify-end"><button class="bg-acc text-button font-bold py-2 px-6 rounded-lg focus:outline-none focus:ring focus:ring-stone-300 hover:scale-105 transition-all duration-200" type="submit">Save</button></div></form></div>`);
  });
}
export {
  _page as default
};
