import { h as head, b as attr_class, a as attr, c as ensure_array_like, s as stringify, e as escape_html, d as derived, f as clsx } from "../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../chunks/exports.js";
import "../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../chunks/root.js";
import "../../../../chunks/state.svelte.js";
import { P as Pagination } from "../../../../chunks/Pagination.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const pageFilters = derived(() => ({
      id: template().filters.id,
      probe_id: template().filters.probe_id,
      src_mac: template().filters.src_mac,
      dst_mac: template().filters.dst_mac,
      src_addr: template().filters.src_addr,
      dst_addr: template().filters.dst_addr,
      src_port: template().filters.src_port,
      dst_port: template().filters.dst_port,
      payload_string: template().filters.payload_string
    }));
    let filterId = "";
    let filterProbeId = "";
    let filterSrcMac = "";
    let filterDstMac = "";
    let filterSrcAddr = "";
    let filterDstAddr = "";
    let filterSrcPort = "";
    let filterDstPort = "";
    let filterPayloadString = "";
    const thClass = "px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-sat-l text-muted-foreground";
    head("88ug10", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Packets</title>`);
      });
    });
    $$renderer2.push(`<div class="w-full mx-auto mb-10 md:mb-5"><div class="flex flex-col justify-center items-center py-6"><h2 class="text-4xl font-bold text-sat-xl">Packets</h2></div> <div class="overflow-x-auto rounded-lg border border-base bg-cards"><table class="divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col"${attr_class(clsx(thClass))}>ID</th><th scope="col"${attr_class(clsx(thClass))}>Probe</th><th scope="col"${attr_class(clsx(thClass))}>Source MAC</th><th scope="col"${attr_class(clsx(thClass))}>Destination MAC</th><th scope="col"${attr_class(clsx(thClass))}>Source IP</th><th scope="col"${attr_class(clsx(thClass))}>Destination IP</th><th scope="col"${attr_class(clsx(thClass))}>Source Port</th><th scope="col"${attr_class(clsx(thClass))}>Destination Port</th><th scope="col"${attr_class(clsx(thClass))}>Payload</th><th scope="col"${attr_class(clsx(thClass))}>Captured At</th><th scope="col"${attr_class(clsx(thClass))}>Actions</th></tr><tr><td class="px-4 py-2"><input type="text" id="filter-id"${attr("value", filterId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-probe_id"${attr("value", filterProbeId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-src_mac"${attr("value", filterSrcMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-dst_mac"${attr("value", filterDstMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-src_addr"${attr("value", filterSrcAddr)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-dst_addr"${attr("value", filterDstAddr)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-src_port"${attr("value", filterSrcPort)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-dst_port"${attr("value", filterDstPort)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-payload_string"${attr("value", filterPayloadString)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"></td><td class="px-4 py-2 flex gap-2"><button type="button" id="filter-button" class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button> <button type="button" id="reset-button" class="px-3 py-1 rounded-md text-button text-sm bg-acc-l hover:bg-muted/20 transition-colors">Reset</button></td></tr></thead><tbody class="divide-y"><!--[-->`);
    const each_array = ensure_array_like(template().packets);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let packet = each_array[$$index];
      $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm"><a${attr("href", `/packet/${stringify(packet.id)}`)} class="text-primary hover:underline">${escape_html(packet.id)}</a></td><td class="px-4 py-3 font-mono text-sm"><a${attr("href", `/probe/${stringify(packet.probe_id)}`)} class="text-primary hover:underline">${escape_html(packet.probe_id)}</a></td><td class="px-4 py-3 text-sm text-sat-l font-mono">${escape_html(packet.src_mac)}</td><td class="px-4 py-3 text-sm text-sat-l font-mono">${escape_html(packet.dst_mac)}</td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html(packet.src_addr)}</span></td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html(packet.dst_addr)}</span></td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html(packet.src_port)}</span></td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html(packet.dst_port)}</span></td><td class="px-4 py-3 text-sm text-sat-l">`);
      if (packet.payload_string) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="font-mono">${escape_html(packet.payload_string.slice(0, 42))}</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="text-muted-foreground">—</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html(packet.captured_at ?? "")}</span></td><td class="px-4 py-2"></td></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().packets.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No packets found.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> `);
    Pagination($$renderer2, {
      pageInfo: template().page_info,
      basePath: "/packet",
      filters: pageFilters()
    });
    $$renderer2.push(`<!----></div>`);
  });
}
export {
  _page as default
};
