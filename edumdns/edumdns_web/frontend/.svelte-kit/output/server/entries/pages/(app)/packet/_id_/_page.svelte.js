import { h as head, a as attr, s as stringify, e as escape_html, d as derived } from "../../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../../chunks/exports.js";
import "../../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../../chunks/root.js";
import "../../../../../chunks/state.svelte.js";
import { E as ErrorAlert } from "../../../../../chunks/ErrorAlert.js";
import { h as hasPermission } from "../../../../../chunks/types.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const packet = derived(() => template().packet);
    const canUpdate = derived(() => hasPermission(template().permissions, "Update"));
    const canDelete = derived(() => hasPermission(template().permissions, "Delete"));
    let probeId = "";
    let srcMac = "";
    let dstMac = "";
    let srcAddr = "";
    let dstAddr = "";
    let srcPort = "";
    let dstPort = "";
    let metadataError = null;
    let reassignError = null;
    let deleteError = null;
    head("ordsos", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Packet ${escape_html(packet().id)}</title>`);
      });
    });
    $$renderer2.push(`<div class="2xl:w-5/6 w-full mx-auto px-4 sm:px-8"><div class="flex items-center justify-between"><h1 class="text-4xl font-semibold text-sat-l">Packet Detail</h1></div> <div class="flex items-center gap-2 mb-6"><a href="/packet" class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors">←</a> `);
    if (canDelete()) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button title="Delete packet" class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md"><i class="fa-solid fa-trash"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (canUpdate()) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<a${attr("href", `/packet/${stringify(packet().id)}/update-payload`)} class="flex items-center justify-center w-10 h-10 bg-acc hover:bg-acc-l rounded-md text-button shadow-md" title="Edit packet"><i class="fa-solid fa-pencil"></i></a>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> `);
    ErrorAlert($$renderer2, { message: deleteError });
    $$renderer2.push(`<!----> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><div class="grid grid-cols-1 lg:grid-cols-2 gap-4"><div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">ID</span> <span class="font-mono text-code"><code>${escape_html(packet().id)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Probe ID</span> <span class="font-mono"><a class="hover:underline"${attr("href", `/probe/${stringify(packet().probe_id)}`)}>${escape_html(packet().probe_id)}</a></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Device</span> <span id="device-id-field" class="font-mono text-code flex items-center gap-2">`);
    {
      $$renderer2.push("<!--[-1-->");
      if (template().device_id == null) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="text-muted-foreground text-sat-m">—</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<a${attr("href", `/device/${stringify(template().device_id)}`)} id="device-id-link">${escape_html(template().device_id)}</a>`);
      }
      $$renderer2.push(`<!--]--> `);
      if (canUpdate()) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<button id="edit-device-id-btn" class="text-xs text-acc hover:text-acc-xl" title="Edit Device" type="button"><i class="fa-solid fa-pen"></i></button>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]-->`);
    }
    $$renderer2.push(`<!--]--></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Captured at</span> <span class="text-sat-l">${escape_html(packet().captured_at ?? "")}</span></div></div> `);
    ErrorAlert($$renderer2, { message: reassignError });
    $$renderer2.push(`<!----></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium mb-4 text-sat-l">Packet metadata</h3> <p class="text-xs text-sat-m mt-1">Change these settings may reassign the packet to a different device.</p> <form class="gap-4"><input type="hidden" id="packet_id" name="id"${attr("value", packet().id)}/> <div class="flex flex-col"><label for="probe_id" class="text-xs uppercase tracking-wide text-forms">Probe ID</label> <input id="probe_id" name="probe_id"${attr("value", probeId)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="src_mac" class="text-xs uppercase tracking-wide text-forms mt-4">Source MAC</label> <input id="src_mac" name="src_mac"${attr("value", srcMac)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="src_mac" class="text-xs uppercase tracking-wide text-forms mt-4">Destination MAC</label> <input id="dst_mac" name="dst_mac"${attr("value", dstMac)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="src_addr" class="text-xs uppercase tracking-wide text-forms mt-4">Source Address</label> <input id="src_addr" name="src_addr"${attr("value", srcAddr)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="dst_addr" class="text-xs uppercase tracking-wide text-forms mt-4">Destination Address</label> <input id="dst_addr" name="dst_addr"${attr("value", dstAddr)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="src_port" class="text-xs uppercase tracking-wide text-forms mt-4">Source Port</label> <input id="src_port" name="src_port"${attr("value", srcPort)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="dst_port" class="text-xs uppercase tracking-wide text-forms mt-4">Destination Port</label> <input id="dst_port" name="dst_port"${attr("value", dstPort)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div></div> `);
    if (canUpdate()) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="md:col-span-2 flex items-center gap-2 pt-2"><button type="submit" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors">Save</button> <button type="button" class="inline-flex items-center rounded-md bg-acc-l px-4 py-2 text-sm font-medium text-button transition-colors">Reset</button></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></form> `);
    ErrorAlert($$renderer2, { message: metadataError });
    $$renderer2.push(`<!----></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium text-sat-l">Payload</h3> `);
    if (packet().payload && packet().payload.length > 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="rounded-lg overflow-x-auto"><pre><code>${escape_html(packet().payload)}</code></pre></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="rounded-lg bg-panes text-sat-m">— No payload —</div>`);
    }
    $$renderer2.push(`<!--]--></div></div>`);
  });
}
export {
  _page as default
};
