import { h as head, e as escape_html, a as attr, c as ensure_array_like, s as stringify, d as derived } from "../../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../../chunks/exports.js";
import "../../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../../chunks/root.js";
import "../../../../../chunks/state.svelte.js";
import { E as ErrorAlert } from "../../../../../chunks/ErrorAlert.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const group = derived(() => template().group);
    let deleteError = null;
    let editName = "";
    let editDescription = "";
    let settingsError = null;
    let userSearch = "";
    let addUsersError = null;
    let removeUserError = null;
    head("5hf07x", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - ${escape_html(group().name)}</title>`);
      });
    });
    $$renderer2.push(`<div class="lg:w-3/4 w-full mx-auto px-4 sm:px-8 mb-10 md:mb-6"><div class="flex items-center justify-between mb-4"><h2 class="text-3xl font-bold text-sat-xl">${escape_html(group().name)}</h2> <button type="button" class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md" title="Delete group" aria-label="Delete group"><i class="fa-solid fa-trash"></i></button></div> `);
    ErrorAlert($$renderer2, { message: deleteError });
    $$renderer2.push(`<!----> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium mb-4 text-sat-l">Group Settings</h3> <div class="flex flex-col mb-4"><span class="text-xs uppercase tracking-wide text-sat-m">ID</span> <span class="font-mono text-code"><code>${escape_html(group().id)}</code></span></div> <form class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="name" class="text-xs uppercase tracking-wide text-sat-m">Name</label> <input id="name" name="name" type="text" placeholder="Group name" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"${attr("value", editName)}/> <p class="text-xs text-sat-m mt-1">Optional name for the group.</p></div> <div class="flex flex-col md:col-span-2"><label for="description" class="text-xs uppercase tracking-wide text-sat-m">Description</label> <textarea id="description" name="description" placeholder="Group description" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc" rows="3">`);
    const $$body = escape_html(editDescription);
    if ($$body) {
      $$renderer2.push(`${$$body}`);
    }
    $$renderer2.push(`</textarea> <p class="text-xs text-sat-m mt-1">Optional description of this group.</p></div> <div class="md:col-span-2 flex items-center gap-2 pt-2"><button type="submit" class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium text-acc-cta transition-colors">Save</button> <button type="button" class="inline-flex items-center rounded-md text-button bg-acc-l px-4 py-2 text-sm font-medium text-sat-l hover:bg-panes transition-colors">Reset</button></div> <div class="md:col-span-2">`);
    ErrorAlert($$renderer2, { message: settingsError });
    $$renderer2.push(`<!----> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></form></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-semibold text-sat-l mb-4">Add users to this group</h3> <form id="add-users-form" class="space-y-4"><div class="relative"><label for="user-search" class="sr-only">Search users</label> <input id="user-search" name="q" type="text" placeholder="Search users by name or email..." class="w-full rounded-md border border-base bg-panes px-3 py-2 text-sat-l"${attr("value", userSearch)}/> <p class="text-xs text-sat-m mt-1">Type to search. Select users below to add.</p></div> <div class="relative"><div id="user-search-results" class="max-h-64 overflow-auto rounded-md border border-base bg-panes" aria-live="polite">`);
    {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="px-3 py-2 text-sat-m">Start typing to search for users…</div>`);
    }
    $$renderer2.push(`<!--]--></div></div> <div class="flex justify-end gap-2"><button type="submit" class="inline-flex items-center gap-2 rounded-md bg-acc text-button px-3 py-2 text-sm text-sat-l font-medium hover:bg-muted/20 transition-colors" title="Add selected users" aria-label="Add selected users"><i class="fa-solid fa-user-plus"></i> Add users</button></div> `);
    ErrorAlert($$renderer2, { message: addUsersError });
    $$renderer2.push(`<!----></form></div> <div id="group-users" class="rounded-lg border border-base bg-cards p-6"><h3 class="text-2xl font-semibold text-sat-l mb-4">Users in this group</h3> `);
    if (template().users.length > 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="overflow-x-auto rounded-lg"><table class="min-w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Email</th><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
      const each_array_1 = ensure_array_like(template().users);
      for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
        let u = each_array_1[$$index_1];
        $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/user/${stringify(u.id)}`)}>${escape_html(u.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(u.name)} ${escape_html(u.surname)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(u.email)}</td><td class="px-4 py-3 text-sm text-sat-l"><button type="button" class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors" title="Delete user from group"><i class="fa-solid fa-trash"></i></button></td></tr>`);
      }
      $$renderer2.push(`<!--]--></tbody></table></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="p-4 text-muted-foreground">No users in this group.</div>`);
    }
    $$renderer2.push(`<!--]--> `);
    ErrorAlert($$renderer2, { message: removeUserError, class: "mt-3" });
    $$renderer2.push(`<!----></div></div>`);
  });
}
export {
  _page as default
};
