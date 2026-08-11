import { h as head, a as attr, c as ensure_array_like, s as stringify, e as escape_html, d as derived } from "../../../../chunks/index2.js";
import { g as goto } from "../../../../chunks/client.js";
import { b as buildQuery } from "../../../../chunks/api.js";
import { E as ErrorAlert } from "../../../../chunks/ErrorAlert.js";
import { P as Pagination } from "../../../../chunks/Pagination.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const pageFilters = derived(() => ({
      id: template().filters.id,
      owner_id: template().filters.owner_id,
      location_id: template().filters.location_id,
      adopted: template().filters.adopted,
      mac: template().filters.mac,
      ip: template().filters.ip,
      name: template().filters.name
    }));
    let filterId = "";
    let filterName = "";
    let filterOwnerId = "";
    let filterMac = "";
    let filterIp = "";
    let filterAdopted = "";
    async function runSearch() {
      await goto(`/probe${buildQuery({
        id: filterId.trim(),
        name: filterName.trim(),
        owner_id: filterOwnerId.trim(),
        mac: filterMac.trim(),
        ip: filterIp.trim(),
        adopted: filterAdopted
      })}`);
    }
    let newProbeName = "";
    let createError = null;
    head("1mvrtag", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Probes</title>`);
      });
    });
    $$renderer2.push(`<div class="w-full mx-auto mb-10 md:mb-5"><div class="flex flex-col justify-center items-center py-6"><h2 class="text-4xl font-bold text-sat-xl">Probes</h2></div> `);
    if (template().user.has_groups || template().user.user.admin) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="rounded-lg border border-base bg-cards p-6 mb-6"><h3 class="text-2xl font-semibold text-forms mb-4">New Probe</h3> <form class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="name" class="text-xs uppercase text-forms tracking-wide">Name</label> <input id="name" name="name" type="text" required="" class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter probe name"${attr("value", newProbeName)}/></div> <div class="md:col-span-2"><button type="submit" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button hover:bg-acc-xl transition-colors">Create Probe</button></div></form> `);
      ErrorAlert($$renderer2, { message: createError });
      $$renderer2.push(`<!----> `);
      {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <div class="overflow-x-auto rounded-lg border border-base bg-cards"><table class="w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Owner</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">MAC</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">IP</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Adopted</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">First Connected At</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Last Connected At</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr><tr><td class="px-4 py-2"><input type="text" id="filter-id"${attr("value", filterId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-name"${attr("value", filterName)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-owner_id"${attr("value", filterOwnerId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-mac"${attr("value", filterMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-ip"${attr("value", filterIp)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2">`);
    $$renderer2.select(
      {
        id: "filter-adopted",
        class: "w-full rounded-md border border-base px-2 py-1 text-sm",
        value: filterAdopted,
        onchange: runSearch
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "" }, ($$renderer4) => {
          $$renderer4.push(`All`);
        });
        $$renderer3.option({ value: "true" }, ($$renderer4) => {
          $$renderer4.push(`Adopted`);
        });
        $$renderer3.option({ value: "false" }, ($$renderer4) => {
          $$renderer4.push(`Not Adopted`);
        });
      }
    );
    $$renderer2.push(`</td><td class="px-4 py-2"></td><td class="px-4 py-2"></td><td class="px-4 py-2 flex gap-2"><button type="button" id="filter-button" class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button> <button type="button" id="reset-button" class="px-3 py-1 rounded-md text-sm bg-acc-l text-button hover:bg-muted/20 transition-colors">Reset</button></td></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
    const each_array = ensure_array_like(template().probes);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let probe = each_array[$$index];
      $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l whitespace-nowrap"><a${attr("href", `/probe/${stringify(probe.id)}`)} class="text-primary hover:underline">${escape_html(probe.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">`);
      if (probe.name !== null) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`${escape_html(probe.name)}`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="text-muted-foreground">—</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l">`);
      if (probe.owner_id !== null) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<a${attr("href", `/user/${stringify(probe.owner_id)}`)}>${escape_html(probe.owner_id)}</a>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="text-muted-foreground">—</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(probe.mac)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(probe.ip)}</td><td class="px-4 py-3 text-sm">`);
      if (probe.adopted) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Yes</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">No</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(probe.first_connected_at)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(probe.last_connected_at)}</td><td class="px-4 py-3 text-sm text-sat-l"></td></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().probes.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No probes found.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> `);
    Pagination($$renderer2, {
      pageInfo: template().page_info,
      basePath: "/probe",
      filters: pageFilters()
    });
    $$renderer2.push(`<!----></div>`);
  });
}
export {
  _page as default
};
