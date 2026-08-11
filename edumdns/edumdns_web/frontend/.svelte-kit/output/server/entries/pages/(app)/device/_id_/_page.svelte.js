import { h as head, e as escape_html, a as attr, s as stringify, c as ensure_array_like, d as derived } from "../../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../../chunks/exports.js";
import "../../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../../chunks/root.js";
import "../../../../../chunks/state.svelte.js";
import { E as ErrorAlert } from "../../../../../chunks/ErrorAlert.js";
import { P as Pagination } from "../../../../../chunks/Pagination.js";
import { h as hasPermission } from "../../../../../chunks/types.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const device = derived(() => template().device);
    const permissions = derived(() => template().permissions);
    function can(permission) {
      return hasPermission(permissions(), permission);
    }
    let actionError = null;
    let settingsName = "";
    let settingsMac = "";
    let settingsIp = "";
    let settingsPort = "";
    let settingsDuration = "";
    let settingsInterval = "";
    let settingsAclPassword = "";
    let settingsAclSrcCidr = "";
    let settingsAclApHostnameRegex = "";
    let settingsProxy = false;
    let settingsExclusive = false;
    let targetIp = "";
    let targetPort = "";
    let permanent = false;
    const pageFilters = derived(() => ({
      id: template().filters.id,
      src_mac: template().filters.src_mac,
      dst_mac: template().filters.dst_mac,
      src_addr: template().filters.src_addr,
      dst_addr: template().filters.dst_addr,
      src_port: template().filters.src_port,
      dst_port: template().filters.dst_port,
      payload_string: template().filters.payload_string
    }));
    let filterId = "";
    let filterSrcMac = "";
    let filterDstMac = "";
    let filterSrcAddr = "";
    let filterDstAddr = "";
    let filterSrcPort = "";
    let filterDstPort = "";
    let filterPayloadString = "";
    head("6ehhb2", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Device ${escape_html(device().name ?? device().id)}</title>`);
      });
    });
    $$renderer2.push(`<div class="2xl:w-5/6 w-full mx-auto px-4 sm:px-8"><div class="flex items-center justify-between"><h1 class="text-4xl font-semibold text-sat-xl">Device ${escape_html(device().name !== null ? device().name : device().id)}</h1></div> <div class="flex items- gap-2 mb-6"><a href="/device" class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors">←</a> <div class="flex items-center gap-2"><button class="flex items-center justify-center w-10 h-10 bg-blue-400 hover:bg-blue-500 rounded-md text-button shadow-md" title="Open device transmit/discovery page"><i class="fa-solid fa-rss"></i></button> `);
    if (can("Update")) {
      $$renderer2.push("<!--[0-->");
      if (device().published) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<button class="flex items-center justify-center w-10 h-10 bg-fuchsia-400 hover:bg-fuchsia-500 rounded-md text-button shadow-md" title="Unpublish (hide) device"><i class="fa-solid fa-eye-slash"></i></button>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<button class="flex items-center justify-center w-10 h-10 bg-lime-500 hover:bg-lime-600 rounded-md text-button shadow-md" title="Publish device (available for public users)"><i class="fa-solid fa-eye"></i></button>`);
      }
      $$renderer2.push(`<!--]-->`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (can("Delete")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md" title="Delete device"><i class="fa-solid fa-trash"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (can("Create")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="flex items-center justify-center w-10 h-10 bg-acc hover:bg-acc-l rounded-md text-button shadow-md" title="Craft a new packet"><i class="fa-solid fa-plus"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></div> `);
    ErrorAlert($$renderer2, { message: actionError });
    $$renderer2.push(`<!----> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4"><div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">ID</span> <span class="font-mono text-code"><code>${escape_html(device().id)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Probe ID</span> <span class="font-mono"><a class="hover:underline"${attr("href", `/probe/${stringify(device().probe_id)}`)}>${escape_html(device().probe_id)}</a></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Discovered At</span> <span class="text-sat-l">${escape_html(device().discovered_at)}</span></div></div></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium mb-4 text-sat-l">Device Settings</h3> <form id="device-update-form" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"><div class="flex flex-col"><label for="name" class="text-xs uppercase tracking-wide text-forms">Name</label> <input id="name" name="name" type="text"${attr("value", settingsName)} placeholder="Friendly name" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Optional friendly name for the device.</p></div> <div class="flex flex-col"><label for="mac" class="text-xs uppercase tracking-wide text-forms">MAC</label> <input id="mac" name="mac"${attr("value", settingsMac)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="ip" class="text-xs uppercase tracking-wide text-forms">IP</label> <input id="ip" name="ip"${attr("value", settingsIp)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="port" class="text-xs uppercase tracking-wide text-forms">Port</label> <input id="port" name="port" type="number" min="1" max="65535"${attr("value", settingsPort)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/></div> <div class="flex flex-col"><label for="duration" class="text-xs uppercase tracking-wide text-forms">Duration</label> <input id="duration" name="duration" type="number" min="0" step="1"${attr("value", settingsDuration)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/> <p class="text-xs text-sat-m mt-1">Duration in seconds.</p></div> <div class="flex flex-col"><label for="interval" class="text-xs uppercase tracking-wide text-forms">Interval</label> <input id="interval" name="interval" type="number" min="0" step="1"${attr("value", settingsInterval)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" required=""/> <p class="text-xs text-sat-m mt-1">Interval in milliseconds.</p></div> <div class="flex flex-col"><label for="acl_password" class="text-xs uppercase tracking-wide text-forms">Password</label> <input id="acl_password" name="acl_password"${attr("value", settingsAclPassword)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Secret"/> <p class="text-xs text-sat-m mt-1">Password clients must provide to initiate packet transmission</p></div> <div class="flex flex-col"><label for="acl_src_cidr" class="text-xs uppercase tracking-wide text-forms">SRC SUBNET</label> <input id="acl_src_cidr" name="acl_src_cidr"${attr("value", settingsAclSrcCidr)} class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" placeholder="e.g., 192.168.1.0/24"/> <p class="text-xs text-sat-m mt-1">Client source IP subnet</p></div> <div class="flex flex-col"><label for="acl_ap_hostname_regex" class="text-xs uppercase tracking-wide text-forms">AP Hostname REGEX</label> <input id="acl_ap_hostname_regex" name="acl_ap_hostname_regex"${attr("value", settingsAclApHostnameRegex)} placeholder="Regex" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Regex over the hostname of an AP a client is connected to</p></div> <div class="flex flex-col"><label class="inline-flex items-center mb-2"><input type="checkbox" name="proxy" class="rounded border-gray-300 text-acc focus:ring-acc"${attr("checked", settingsProxy, true)}/> <span class="ml-2 text-sat-m">Use Proxy</span></label> <label class="inline-flex items-center"><input type="checkbox" name="exclusive" class="rounded border-gray-300 text-acc focus:ring-acc"${attr("checked", settingsExclusive, true)}/> <span class="ml-2 text-sat-m">Exclusive discovery</span></label></div></form> `);
    if (can("Update")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="md:col-span-2 flex items-center gap-2 pt-2"><button type="submit" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors">Save</button> <button type="reset" class="inline-flex items-center rounded-md bg-acc-l px-4 py-2 text-sm font-medium text-button transition-colors">Reset</button></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> <div class="rounded-lg border border-base bg-cards p-6 mb-6"><h3 class="text-2xl font-medium mb-4 text-sat-l">Request Packet Transmission</h3> <form class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"><div class="flex flex-col"><label for="target_ip" class="text-xs uppercase tracking-wide text-forms">Target IP</label> <input id="target_ip" name="target_ip" type="text" inputmode="numeric" placeholder="e.g., 8.8.8.8"${attr("value", targetIp)} required="" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Destination IPv4/IPv6 subnet.</p></div> <div class="flex flex-col"><label for="target_port" class="text-xs uppercase tracking-wide text-forms">Target Port</label> <input id="target_port" name="target_port" type="number" min="1" max="65535" placeholder="e.g., 53"${attr("value", targetPort)} required="" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Destination TCP/UDP port (1–65535).</p></div> <div class="md:col-span-2 flex items-center gap-2"><input id="permanent" name="permanent" type="checkbox" class="h-4 w-4 rounded border-base bg-panes text-acc focus:ring-2 focus:ring-acc"${attr("checked", permanent, true)}/> <label for="permanent" class="text-sm text-sat-l">Permanent</label></div> <div class="md:col-span-2 flex items-center gap-2"><button type="button" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors">Transmit</button></div></form></div> <div class="rounded-lg border border-base bg-cards p-6 mb-6"><h3 class="text-2xl font-medium mb-4 text-sat-l">Packet Transmissions in progress</h3> <div class="overflow-x-auto"><table class="min-w-full divide-y divide-base"><thead class="bg-panes"><tr><th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide">User</th><th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide">Target IP</th><th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide">Target Port</th><th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide">Permanent</th><th class="px-4 py-2 text-left text-xs font-medium text-sat-m uppercase tracking-wide">Valid Until</th><th class="px-4 py-2 text-right text-xs font-medium text-sat-m uppercase tracking-wide">Actions</th><th class="px-4 py-2 text-right text-xs font-medium text-sat-m uppercase tracking-wide"></th></tr></thead><tbody class="divide-y divide-base">`);
    if (template().packet_transmit_requests.length > 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<!--[-->`);
      const each_array = ensure_array_like(template().packet_transmit_requests);
      for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
        let r = each_array[$$index];
        $$renderer2.push(`<tr class="bg-table rounded-lg transition-colors"><td class="px-4 py-2 text-sat-l"><a${attr("href", `/user/${stringify(r.user_id)}`)}>${escape_html(r.user_id)}</a></td><td class="px-4 py-2 text-sat-l">${escape_html(r.target_ip)}</td><td class="px-4 py-2 text-sat-l">${escape_html(r.target_port)}</td><td class="px-4 py-2 text-sat-l">${escape_html(r.permanent)}</td><td class="px-4 py-2 text-sat-l">${escape_html(r.until)}</td><td class="px-4 py-2"><div class="flex justify-end"><button type="button" class="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors" title="Extend Discovery"><i class="fa-solid fa-arrows-rotate text-blue-400 hover:text-blue-500"></i></button></div></td><td class="px-4 py-2"><div class="flex justify-end"><button type="button" class="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors" title="Delete"><i class="fa fa-trash text-red-400 hover:text-red-500"></i></button></div></td></tr>`);
      }
      $$renderer2.push(`<!--]-->`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<tr><td colspan="6" class="px-4 py-6 text-center text-sat-m">No packet transmissions.</td></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table></div></div> <div class="overflow-x-auto rounded-lg border border-base bg-cards"><div class="flex flex-col justify-center items-center py-4"><h2 class="text-3xl font-medium text-sat-xl">Packets</h2></div> <table class="min-w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Src MAC</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Dst MAC</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Src Addr</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Dst Addr</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Src Port</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Dst Port</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Payload</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Captured At</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr><tr><td class="px-4 py-2"><input type="text" id="filter-id"${attr("value", filterId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-src_mac"${attr("value", filterSrcMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-dst_mac"${attr("value", filterDstMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-src_addr"${attr("value", filterSrcAddr)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-dst_addr"${attr("value", filterDstAddr)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-src_port"${attr("value", filterSrcPort)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-dst_port"${attr("value", filterDstPort)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-payload_string"${attr("value", filterPayloadString)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"></td><td class="px-4 py-2 flex gap-2"><button type="button" id="filter-button" class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button> <button type="button" id="reset-button" class="px-3 py-1 rounded-md text-button text-sm bg-acc-l hover:bg-muted/20 transition-colors">Reset</button></td></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
    const each_array_1 = ensure_array_like(template().packets);
    for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
      let packet = each_array_1[$$index_1];
      $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/packet/${stringify(packet.id)}`)} class="text-primary hover:underline">${escape_html(packet.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(packet.src_mac)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(packet.dst_mac)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(packet.src_addr)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(packet.dst_addr)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(packet.src_port)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(packet.dst_port)}</td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html((packet.payload_string ?? "").slice(0, 100))}</span></td><td class="px-4 py-3 text-sm text-sat-l"><span class="font-mono">${escape_html(packet.captured_at)}</span></td>`);
      if (can("Delete")) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<td class="px-4 py-3 text-sm text-sat-l"><button class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors" title="Delete Packet"><i class="fa-solid fa-trash"></i></button></td>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().packets.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No packets found for this device.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> `);
    Pagination($$renderer2, {
      pageInfo: template().page_info,
      basePath: `/device/${stringify(device().id)}`,
      filters: pageFilters()
    });
    $$renderer2.push(`<!----></div>`);
  });
}
export {
  _page as default
};
