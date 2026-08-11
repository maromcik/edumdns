import { h as head, b as attr_class, e as escape_html, a as attr, s as stringify, c as ensure_array_like, d as derived } from "../../../../../chunks/index2.js";
import { g as goto } from "../../../../../chunks/client.js";
import { b as buildQuery } from "../../../../../chunks/api.js";
import { E as ErrorAlert } from "../../../../../chunks/ErrorAlert.js";
import { P as Pagination } from "../../../../../chunks/Pagination.js";
import { h as hasPermission } from "../../../../../chunks/types.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const probe = derived(() => template().probe);
    const permissions = derived(() => template().permissions);
    const isAdmin = derived(() => template().user.user.admin);
    function can(permission) {
      return hasPermission(permissions(), permission);
    }
    let alive = null;
    let actionError = null;
    let settingsName = "";
    let settingsPsk = "";
    const canModifyConfig = derived(() => hasPermission(permissions(), "ModifyConfig") || isAdmin());
    let cfgEdits = [];
    let newCfgInterface = "";
    let newCfgFilter = "";
    let filterId = "";
    let filterName = "";
    let filterMac = "";
    let filterIp = "";
    let filterPort = "";
    let filterPublished = "";
    let filterExclusive = "";
    let filterProxy = "";
    async function runSearch() {
      await goto(`/probe/${probe().id}${buildQuery({
        id: filterId.trim(),
        name: filterName.trim(),
        mac: filterMac.trim(),
        ip: filterIp.trim(),
        port: filterPort.trim(),
        published: filterPublished,
        exclusive: filterExclusive,
        proxy: filterProxy
      })}`);
    }
    const pageFilters = derived(() => ({
      id: template().filters.id,
      name: template().filters.name,
      mac: template().filters.mac,
      ip: template().filters.ip,
      port: template().filters.port,
      published: template().filters.published,
      exclusive: template().filters.exclusive,
      proxy: template().filters.proxy
    }));
    head("hozn74", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Probe ${escape_html(probe().name ?? probe().id)}</title>`);
      });
    });
    $$renderer2.push(`<div class="2xl:w-5/6 w-full mx-auto px-4 sm:px-8"><div class="flex items-center justify-between"><h1 class="text-4xl font-semibold text-sat-xl flex items-center gap-2"><span${attr_class("inline-block w-3 h-3 rounded-full", void 0, {
      "bg-gray-400": alive === null,
      "bg-green-500": alive === true,
      "bg-red-500": alive === false
    })}></span> Probe `);
    if (probe().name === null) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`${escape_html(probe().id.slice(0, 13))}...`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`${escape_html(probe().name)}`);
    }
    $$renderer2.push(`<!--]--></h1></div> <div class="flex items-center gap-2 mb-6"><div class="flex items-center gap-2"><a href="/probe" class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors">←</a> `);
    if (can("Reconnect")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="bg-yellow-400 hover:bg-yellow-500 flex items-center justify-center w-10 h-10 rounded-md text-button shadow-md" title="Reconnect probe"><i class="fa-solid fa-rotate-right"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (probe().adopted && can("Forget")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="bg-purple-400 hover:bg-purple-500 items-center justify-center w-10 h-10 rounded-md text-button shadow-md" title="Stop (forget) probe"><i class="fa-solid fa-stop"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (!probe().adopted && can("Adopt")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="bg-green-400 hover:bg-green-500 items-center justify-center w-10 h-10 rounded-md text-button shadow-md" title="Resume (adopt) probe"><i class="fa-solid fa-play"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (can("Delete")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="bg-red-600 hover:bg-red-700 items-center justify-center w-10 h-10 rounded-md text-button shadow-md" title="Permanently delete probe"><i class="fa-solid fa-trash"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> `);
    if (can("Create")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<button class="bg-acc hover:bg-acc-xl items-center justify-center w-10 h-10 rounded-md text-button shadow-md" title="Add a new device"><i class="fa-solid fa-plus"></i></button>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></div> `);
    ErrorAlert($$renderer2, { message: actionError });
    $$renderer2.push(`<!----> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"><div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">ID</span> <span class="font-mono text-code"><code>${escape_html(probe().id)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Owner</span> <span class="font-mono text-code flex items-center gap-2">`);
    if (probe().owner_id === null) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<span class="text-muted-foreground text-sat-m">—</span>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<a${attr("href", `/user/${stringify(probe().owner_id)}`)}>${escape_html(probe().owner_id)}</a>`);
    }
    $$renderer2.push(`<!--]--> `);
    if (isAdmin()) {
      $$renderer2.push("<!--[0-->");
      {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<button class="text-xs text-acc hover:text-acc-xl" title="Edit owner" type="button"><i class="fa-solid fa-pen"></i></button>`);
      }
      $$renderer2.push(`<!--]-->`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">MAC</span> <span class="font-mono text-code"><code>${escape_html(probe().mac)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">IP</span> <span class="font-mono text-code"><code>${escape_html(probe().ip)}</code></span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">First connected at</span> <span class="text-sat-l">${escape_html(probe().first_connected_at)}</span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Last connected at</span> <span class="text-sat-l">${escape_html(probe().last_connected_at)}</span></div> <div class="flex flex-col"><span class="text-xs uppercase tracking-wide text-sat-m">Adopted</span> <span class="font-mono text-sat-xl">`);
    if (probe().adopted) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Yes</span>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">No</span>`);
    }
    $$renderer2.push(`<!--]--></span></div></div></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium mb-4 text-sat-l">Probe Settings</h3> <form class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="name" class="text-xs uppercase tracking-wide text-sat-m">Name</label> <input id="name" name="name" type="text"${attr("value", settingsName)} placeholder="Friendly name" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Optional friendly name for the probe.</p></div> <div class="flex flex-col"><label for="pre_shared_key" class="text-xs uppercase tracking-wide text-sat-m">Pre-Shared Secret Key</label> <input id="pre_shared_key" name="pre_shared_key" type="text"${attr("value", settingsPsk)} placeholder="Optional pre-shared key" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"/> <p class="text-xs text-sat-m mt-1">Optional Pre-Shared Key for increased security (probe traffic is encrypted nonetheless).</p></div> `);
    if (can("Update")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="md:col-span-2 flex items-center gap-2 pt-2"><button type="submit" class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium transition-colors">Save</button> <button type="button" class="inline-flex items-center rounded-md text-button bg-acc-l px-4 py-2 text-sm font-medium transition-colors">Reset</button></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></form></div> `);
    if (isAdmin()) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="overflow-x-auto rounded-lg border border-base bg-cards mb-8"><div class="flex flex-col justify-center items-center py-4"><h2 class="text-3xl font-medium text-sat-xl">Permissions</h2></div> <div class="overflow-x-auto rounded-lg"><table class="w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Group</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Full</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Read</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Adopt</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Forget</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Reconnect</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ModifyConfig</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Delete</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Update</th><th scope="col" class="px-4 py-3 text-center text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Create</th></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
      const each_array = ensure_array_like(template().permission_matrix);
      for (let $$index_1 = 0, $$length = each_array.length; $$index_1 < $$length; $$index_1++) {
        let [perms, group] = each_array[$$index_1];
        $$renderer2.push(`<tr class="bg-table rounded-lg transition-colors"><td class="px-4 py-3 text-sm text-sat-l"><a${attr("href", `/group/${stringify(group.id)}`)}>${escape_html(group.name)}</a></td><!--[-->`);
        const each_array_1 = ensure_array_like(perms);
        for (let $$index = 0, $$length2 = each_array_1.length; $$index < $$length2; $$index++) {
          let [perm, checked] = each_array_1[$$index];
          $$renderer2.push(`<td class="px-4 py-3 text-sm text-sat-l text-center"><input type="checkbox" class="h-4 w-4 rounded border-base text-acc focus:ring-acc"${attr("checked", checked, true)}${attr("disabled", !canModifyConfig() || perm === "Full" || perm === "Read", true)} aria-label="Toggle permission"/></td>`);
        }
        $$renderer2.push(`<!--]--></tr>`);
      }
      $$renderer2.push(`<!--]--></tbody></table></div></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--> <div class="overflow-x-auto rounded-lg border border-base bg-cards mt-8 mb-8"><div class="flex flex-col justify-center items-center py-4"><h2 class="text-3xl font-medium text-sat-xl">Capture Configs</h2></div> <table class="min-w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Interface</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Filter</th><th scope="col" class="px-4 py-3 text-right text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
    const each_array_2 = ensure_array_like(cfgEdits);
    for (let $$index_2 = 0, $$length = each_array_2.length; $$index_2 < $$length; $$index_2++) {
      let cfg = each_array_2[$$index_2];
      $$renderer2.push(`<tr class="bg-table rounded-lg transition-colors"><td class="px-4 py-3 text-sm text-code"><input type="text" name="interface"${attr("value", cfg.interfaceValue)} class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm" required=""/></td><td class="px-4 py-3 text-sm text-code"><input type="text" name="filter"${attr("value", cfg.filterValue)} class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm" placeholder="optional"/></td><td class="px-4 py-3 text-right">`);
      if (can("ModifyConfig")) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<button type="submit" class="inline-flex items-center rounded-md bg-background px-3 py-1.5 text-m font-medium text-green-700 bg-green-50 hover:bg-green-200 text-primary hover:bg-muted/10 transition-colors" aria-label="Save config" title="Save"><i class="fa-solid fa-floppy-disk mr-1.5"></i></button> <button class="ml-2 inline-flex items-center rounded-md bg-background px-3 py-1.5 text-m font-medium text-red-700 bg-red-50 hover:bg-red-200 transition-colors" type="button" aria-label="Delete config" title="Delete"><i class="fa-solid fa-trash mr-1.5"></i></button>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></td></tr>`);
    }
    $$renderer2.push(`<!--]-->`);
    if (can("ModifyConfig")) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<tr class="hover:bg-muted/5 transition-colors"><td class="px-4 py-3 text-sm text-code"><input type="text" name="interface" class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm" form="cfg-create-form" placeholder="e.g. eth0" required=""${attr("value", newCfgInterface)}/></td><td class="px-4 py-3 text-sm text-code"><input type="text" name="filter" class="w-full rounded-md border border-base bg-background px-2 py-1 font-mono text-sm" form="cfg-create-form" placeholder="optional, e.g. port 53"${attr("value", newCfgFilter)}/></td><td class="px-4 py-3 text-right"><form id="cfg-create-form" class="inline-flex"><button type="submit" class="inline-flex items-center rounded-md border border-base bg-background px-3 py-1.5 text-m font-medium text-acc hover:bg-muted/10 transition-colors" aria-label="Add config" title="Add config"><i class="fa-solid fa-plus mr-1.5"></i> Add config</button></form></td></tr>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().configs.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No probe configs found for this probe.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> <div class="overflow-x-auto rounded-lg border border-base bg-cards mt-8"><div class="flex flex-col justify-center items-center py-4"><h2 class="text-3xl font-medium text-sat-xl">Devices</h2></div> <table class="min-w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">MAC</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">IP</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Port</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Published</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Exclusive</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Proxy</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Discovered At</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr><tr><td class="px-4 py-2"><input type="text" id="filter-id"${attr("value", filterId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-name"${attr("value", filterName)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-mac"${attr("value", filterMac)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-ip"${attr("value", filterIp)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-port"${attr("value", filterPort)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2">`);
    $$renderer2.select(
      {
        id: "filter-published",
        class: "w-full rounded-md border border-base px-2 py-1 text-sm",
        value: filterPublished,
        onchange: runSearch
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
        value: filterExclusive,
        onchange: runSearch
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
        value: filterProxy,
        onchange: runSearch
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
    const each_array_3 = ensure_array_like(template().devices);
    for (let $$index_3 = 0, $$length = each_array_3.length; $$index_3 < $$length; $$index_3++) {
      let device = each_array_3[$$index_3];
      $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/device/${stringify(device.id)}`)} class="text-primary hover:underline">${escape_html(device.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">`);
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
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(device.discovered_at)}</td>`);
      if (can("Delete")) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<td class="px-4 py-3 text-sm text-sat-l"><button class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors" title="Delete device"><i class="fa-solid fa-trash"></i></button></td>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().devices.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No devices found for this probe.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div> `);
    Pagination($$renderer2, {
      pageInfo: template().page_info,
      basePath: `/probe/${probe().id}`,
      filters: pageFilters()
    });
    $$renderer2.push(`<!----></div>`);
  });
}
export {
  _page as default
};
