import { h as head, e as escape_html, a as attr, d as derived } from "../../../../../../chunks/index2.js";
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
    const device = derived(() => template().device);
    const request = derived(() => template().packet_transmit_request);
    let actionError = null;
    let aclPwd = "";
    let targetIp = "";
    let targetPort = "";
    let permanent = false;
    head("jotmbv", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Device ${escape_html(device().name ?? device().id)} Transmit</title>`);
      });
    });
    $$renderer2.push(`<div id="transmit-form" class="max-w-7xl mx-auto px-4 sm:px-8"><section class="text-center py-12 mb-3"><div class="flex items-center justify-center gap-2 mb-8"><button class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors">←</button> <h2 class="text-3xl md:text-4xl font-extrabold text-sat-xl tracking-tight">Discover device ${escape_html(device().name === null ? device().id : device().name)}</h2></div> <div class="rounded-xl bg-cards p-8 shadow-lg mb-10 text-left"><h3 class="text-xl md:text-2xl font-semibold mb-6 text-sat-l flex items-center gap-2"><svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-acc" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2a4 4 0 014-4h6"></path></svg> Device Information</h3> <div class="grid grid-cols-1 md:grid-cols-2 gap-6"><div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">ID</span> <span class="font-mono text-code truncate"><code>${escape_html(device().id)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Name</span> <span class="font-mono text-code truncate"><code>${escape_html(device().name)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Device MAC</span> <span class="font-mono text-code truncate"><code>${escape_html(device().mac)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Device IP</span> <span class="font-mono text-code truncate"><code>${escape_html(device().ip)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Transmit Duration</span> <span class="font-mono text-code truncate"><code>${escape_html(device().duration)} seconds</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Transmit Interval</span> <span class="font-mono text-code truncate"><code>${escape_html(device().interval)} ms</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Via Proxy</span> <span class="font-mono text-code truncate"><code>${escape_html(device().proxy)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Exclusive</span> <span class="font-mono text-code truncate"><code>${escape_html(device().exclusive)}</code></span></div></div></div> `);
    ErrorAlert($$renderer2, { message: actionError });
    $$renderer2.push(`<!----> <div id="transmit-result" class="mt-10"><div class="rounded-2xl bg-cards p-10 shadow-xl"><div class="flex flex-col items-center justify-center gap-8"><div class="flex flex-col items-center gap-3"><span class="text-sm md:text-lg uppercase tracking-wide text-sat-l font-semibold flex items-center gap-2"><i class="fa-solid fa-network-wired text-acc"></i> Your IP Address</span> <div class="px-4 py-2 border border-permanent rounded-lg"><span class="text-2xl font-mono text-sat-xl tracking-tight select-all">${escape_html(template().client_ip)}</span></div></div> `);
    if (template().in_progress !== null && request() === null) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="w-full max-w-lg bg-yellow-50 border-l-4 border-yellow-500 text-yellow-900 p-5 rounded-md text-left"><div class="flex items-center gap-3"><i class="fa-solid fa-triangle-exclamation text-yellow-600 text-xl"></i> <h3 class="text-lg font-semibold">Discovery In Progress</h3></div> <p class="mt-2 text-sm">Another discovery for this device is currently running. Please wait until it
								completes on <span class="font-mono">${escape_html(template().in_progress.until)}</span>.</p></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="flex flex-col items-center justify-center gap-6 w-full">`);
      if (request() !== null) {
        $$renderer2.push("<!--[0-->");
        if (request().until !== null) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<div class="w-full max-w-md"><div class="flex flex-col sm:flex-row items-center justify-between w-full px-8 py-4 rounded-xl border border-permanent"><div><p class="font-semibold text-sat-l"><i class="fa-solid fa-clock text-sat-l text-lg pr-2"></i> Discovery Active</p> <p class="text-sm text-sat-l">Until ${escape_html(request().until)}</p></div> <button type="submit" class="inline-flex items-center gap-2 rounded-lg border border-red-600 bg-red-500 text-button px-4 py-2 text-sm font-semibold hover:bg-red-600 transition"><i class="fa-solid fa-stop"></i> Stop</button></div></div>`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--> <form class="flex flex-col items-center gap-5 w-full max-w-sm bg-base/10 p-6 rounded-xl border border-permanent">`);
        if (device().acl_pwd_hash !== null) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<div class="w-full text-left"><label for="acl_pwd_extend" class="text-xs uppercase tracking-wide text-sat-l mb-1 block">Password</label> <input id="acl_pwd_extend" name="acl_pwd" type="password"${attr("value", aclPwd)} class="w-full rounded-md border border-base bg-bg px-3 py-2 bg-panes text-sat-l placeholder-sat-m" placeholder="Enter password"/></div>`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--> <button type="submit" class="inline-flex items-center justify-center gap-3 rounded-xl bg-acc text-button px-6 py-3 text-lg font-semibold hover:bg-acc-xl transition"><i class="fa-solid fa-arrows-rotate"></i> Extend Discovery</button></form>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<form class="flex flex-col items-center gap-5 w-full max-w-sm bg-base/10 p-6 rounded-xl border border-permanent">`);
        if (device().acl_pwd_hash !== null) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<div class="w-full text-left"><label for="acl_pwd" class="text-xs uppercase tracking-wide text-sat-l mb-1 block">Password</label> <input id="acl_pwd" name="acl_pwd" type="password"${attr("value", aclPwd)} class="w-full rounded-md border border-base bg-bg px-3 py-2 bg-panes text-sat-l focus:outline-none placeholder-sat-m" placeholder="Enter password"/></div>`);
        } else {
          $$renderer2.push("<!--[-1-->");
        }
        $$renderer2.push(`<!--]--> <button type="submit" class="inline-flex items-center justify-center gap-3 rounded-xl bg-acc text-button px-6 py-3 text-lg font-semibold hover:bg-primary/90 transition-colors"><i class="fa-solid fa-search"></i> Discover</button></form>`);
      }
      $$renderer2.push(`<!--]--></div>`);
    }
    $$renderer2.push(`<!--]--></div></div></div> <div class="rounded-xl bg-cards p-8 shadow-lg mt-10 text-left"><h3 class="text-xl md:text-2xl font-semibold mb-6 text-sat-l">Request Custom Packet Transmission</h3> <form class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"><div class="flex flex-col"><label for="target_ip" class="text-xs uppercase tracking-wide text-forms">Target IP</label> <input id="target_ip" name="target_ip" type="text" inputmode="numeric" placeholder="e.g., 8.8.8.8"${attr("value", targetIp)} required="" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Destination IPv4/IPv6 subnet.</p></div> <div class="flex flex-col"><label for="target_port" class="text-xs uppercase tracking-wide text-forms">Target Port</label> <input id="target_port" name="target_port" type="number" min="1" max="65535" placeholder="e.g., 53"${attr("value", targetPort)} required="" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Destination TCP/UDP port (1–65535).</p></div> <div class="md:col-span-2 flex items-center gap-2"><input id="permanent" name="permanent" type="checkbox" class="h-4 w-4 rounded border-base bg-panes text-acc focus:ring-2 focus:ring-acc"${attr("checked", permanent, true)}/> <label for="permanent" class="text-sm text-sat-l">Permanent</label></div> <div class="md:col-span-2 flex items-center gap-2"><button type="submit" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors">Transmit</button></div></form></div></section></div>`);
  });
}
export {
  _page as default
};
