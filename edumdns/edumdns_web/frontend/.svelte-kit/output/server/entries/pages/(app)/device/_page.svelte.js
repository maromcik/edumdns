import { h as head, a as attr, c as ensure_array_like, s as stringify, e as escape_html, d as derived } from "../../../../chunks/index2.js";
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
      mac: template().filters.mac,
      ip: template().filters.ip,
      port: template().filters.port,
      name: template().filters.name,
      published: template().filters.published,
      proxy: template().filters.proxy,
      exclusive: template().filters.exclusive
    }));
    let filterId = "";
    let filterProbeId = "";
    let filterName = "";
    let filterMac = "";
    let filterIp = "";
    let filterPort = "";
    let filterPublished = "";
    let filterExclusive = "";
    let filterProxy = "";
    head("14rp6va", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Devices</title>`);
      });
    });
    $$renderer2.push(`<div class="w-full mx-auto mb-10 md:mb-5"><div class="flex flex-col justify-center items-center py-6"><h2 class="text-4xl font-bold text-sat-xl">Devices</h2></div> <div class="overflow-x-auto rounded-lg border border-base bg-cards"><table class="divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Probe</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">MAC</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">IP</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Port</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Published</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Exclusive</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Proxy</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Discovered At</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr><tr><td class="px-4 py-2"><input type="text" id="filter-id"${attr("value", filterId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-probe_id"${attr("value", filterProbeId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-name"${attr("value", filterName)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-mac"${attr("value", filterMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-ip"${attr("value", filterIp)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-port"${attr("value", filterPort)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2">`);
    $$renderer2.select(
      {
        id: "filter-published",
        class: "w-full rounded-md border border-base px-2 py-1 text-sm",
        value: filterPublished
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "" }, ($$renderer4) => {
          $$renderer4.push(`All`);
        });
        $$renderer3.option({ value: "true" }, ($$renderer4) => {
          $$renderer4.push(`Published`);
        });
        $$renderer3.option({ value: "false" }, ($$renderer4) => {
          $$renderer4.push(`Not Published`);
        });
      }
    );
    $$renderer2.push(`</td><td class="px-4 py-2">`);
    $$renderer2.select(
      {
        id: "filter-exclusive",
        class: "w-full rounded-md border border-base px-2 py-1 text-sm",
        value: filterExclusive
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "" }, ($$renderer4) => {
          $$renderer4.push(`All`);
        });
        $$renderer3.option({ value: "true" }, ($$renderer4) => {
          $$renderer4.push(`Exclusive`);
        });
        $$renderer3.option({ value: "false" }, ($$renderer4) => {
          $$renderer4.push(`Not Exclusive`);
        });
      }
    );
    $$renderer2.push(`</td><td class="px-4 py-2">`);
    $$renderer2.select(
      {
        id: "filter-proxy",
        class: "w-full rounded-md border border-base px-2 py-1 text-sm",
        value: filterProxy
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "" }, ($$renderer4) => {
          $$renderer4.push(`All`);
        });
        $$renderer3.option({ value: "true" }, ($$renderer4) => {
          $$renderer4.push(`Proxy`);
        });
        $$renderer3.option({ value: "false" }, ($$renderer4) => {
          $$renderer4.push(`No Proxy`);
        });
      }
    );
    $$renderer2.push(`</td><td class="px-4 py-2"></td><td class="px-4 py-2 flex gap-2"><button type="button" id="filter-button" class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button> <button type="button" id="reset-button" class="px-3 py-1 rounded-md text-sm bg-acc-l text-button hover:bg-muted/20 transition-colors">Reset</button></td></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
    const each_array = ensure_array_like(template().devices);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let device = each_array[$$index];
      $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/device/${stringify(device.id)}`)} class="text-primary hover:underline">${escape_html(device.id)}</a></td><td class="px-4 py-3 text-sm"><a${attr("href", `/probe/${stringify(device.probe_id)}`)} class="text-primary hover:underline">${escape_html(device.probe_id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">`);
      if (device.name !== null) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`${escape_html(device.name)}`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="text-muted-foreground">—</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(device.mac)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(device.ip)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(device.port)}</td><td class="px-4 py-3 text-sm">`);
      if (device.published) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Yes</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">No</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm">`);
      if (device.exclusive) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Yes</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">No</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm">`);
      if (device.proxy) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Yes</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">No</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(device.discovered_at)}</td><td class="px-4 py-2"></td></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().devices.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No devices found.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> `);
    Pagination($$renderer2, {
      pageInfo: template().page_info,
      basePath: "/device",
      filters: pageFilters()
    });
    $$renderer2.push(`<!----></div>`);
  });
}
export {
  _page as default
};
