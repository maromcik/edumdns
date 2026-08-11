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
    const targetUser = derived(() => template().target_user.user);
    let deleteError = null;
    let editName = "";
    let editSurname = "";
    let editEmail = "";
    let editAdmin = false;
    let editDisabled = false;
    let settingsError = null;
    let newPassword = "";
    let confirmPassword = "";
    let passwordError = null;
    let groupSearch = "";
    let addGroupsError = null;
    let removeGroupError = null;
    head("vfrz49", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - ${escape_html(targetUser().name)} ${escape_html(targetUser().surname)}</title>`);
      });
    });
    $$renderer2.push(`<div class="lg:w-3/4 w-full mx-auto px-4 sm:px-8 mb-10 md:mb-6"><div class="flex items-center justify-between mb-4"><h2 class="text-3xl font-bold text-sat-xl">${escape_html(targetUser().name)}
			${escape_html(targetUser().surname)}</h2> <button type="button" class="flex items-center justify-center w-10 h-10 bg-red-600 hover:bg-red-700 rounded-md text-button shadow-md" title="Delete user" aria-label="Delete user"><i class="fa-solid fa-trash"></i></button></div> `);
    ErrorAlert($$renderer2, { message: deleteError });
    $$renderer2.push(`<!----> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium mb-4 text-sat-l">User Settings</h3> <div class="flex flex-col mb-4"><span class="text-xs uppercase tracking-wide text-sat-m">ID</span> <span class="font-mono text-code"><code>${escape_html(targetUser().id)}</code></span></div> <form class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="name" class="text-xs uppercase tracking-wide text-sat-l">Name</label> <input id="name" name="name" type="text" placeholder="First name" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"${attr("value", editName)}/></div> <div class="flex flex-col"><label for="surname" class="text-xs uppercase tracking-wide text-sat-l">Surname</label> <input id="surname" name="surname" type="text" placeholder="Surname" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"${attr("value", editSurname)}/></div> <div class="flex flex-col md:col-span-2"><label for="email" class="text-xs uppercase tracking-wide text-sat-l">Email</label> <input id="email" name="email" type="email" placeholder="user@example.com" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"${attr("value", editEmail)}/></div> <div class="flex items-center gap-4 md:col-span-2 mt-2"><label class="inline-flex items-center"><input type="checkbox" name="admin" value="true" class="rounded border-gray-300 text-acc focus:ring-acc"${attr("checked", editAdmin, true)}/> <span class="ml-2 text-sat-l">Admin</span></label> <label class="inline-flex items-center"><input type="checkbox" name="disabled" value="true" class="rounded border-gray-300 text-acc focus:ring-acc"${attr("checked", editDisabled, true)}/> <span class="ml-2 text-sat-l">Disabled</span></label></div> <div class="md:col-span-2 flex items-center gap-2 pt-2"><button type="submit" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-acc-cta hover:bg-acc-xl transition-colors">Save</button> <button type="button" class="inline-flex items-center rounded-md text-button px-4 py-2 text-sm font-medium bg-acc-l hover:bg-panes transition-colors">Reset</button></div> <div class="md:col-span-2">`);
    ErrorAlert($$renderer2, { message: settingsError });
    $$renderer2.push(`<!----> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></form></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-medium mb-4 text-sat-l">User Password</h3> <form class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="new_password" class="text-xs uppercase tracking-wide text-sat-l">Password</label> <input id="new_password" name="new_password" type="password" placeholder="Enter a new password" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"${attr("value", newPassword)}/></div> <div class="flex flex-col"><label for="confirm_password" class="text-xs uppercase tracking-wide text-sat-l">Confirm Password</label> <input id="confirm_password" name="confirm_password" type="password" placeholder="Enter the password again" class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"${attr("value", confirmPassword)}/></div> <div class="md:col-span-2 flex items-center gap-2 pt-2"><button type="submit" class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium text-acc-cta hover:bg-acc-xl transition-colors">Save</button> <button type="reset" class="inline-flex items-center rounded-md bg-acc-l px-4 py-2 text-sm font-medium text-button hover:bg-panes transition-colors">Reset</button></div> <div class="md:col-span-2">`);
    ErrorAlert($$renderer2, { message: passwordError });
    $$renderer2.push(`<!----> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></form></div> <div class="rounded-lg border border-base bg-cards p-6 mb-8"><h3 class="text-2xl font-semibold text-sat-l mb-4">Add this user to groups</h3> <form id="add-groups-form" class="space-y-4"><div class="relative"><label for="group-search" class="sr-only">Search groups</label> <input id="group-search" name="q" type="text" placeholder="Search users by name or email..." class="w-full rounded-md border border-base bg-panes px-3 py-2 text-sat-l"${attr("value", groupSearch)}/> <p class="text-xs text-sat-m mt-1">Type to search. Select users below to add.</p></div> <div class="relative"><div id="group-search-results" class="max-h-64 overflow-auto rounded-md border border-base bg-panes" aria-live="polite">`);
    {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="px-3 py-2 text-sat-m">Start typing to search for groups…</div>`);
    }
    $$renderer2.push(`<!--]--></div></div> <div class="flex justify-end gap-2"><button type="submit" class="inline-flex items-center gap-2 rounded-md bg-acc px-3 py-2 text-sm text-button font-medium hover:bg-muted/20 transition-colors" title="Add selected users" aria-label="Add selected users"><i class="fa-solid fa-user-plus"></i> Add groups</button></div> `);
    ErrorAlert($$renderer2, { message: addGroupsError });
    $$renderer2.push(`<!----></form></div> <div id="user-groups" class="rounded-lg border border-base bg-cards p-6"><h3 class="text-2xl font-semibold text-sat-l mb-4">Groups for this user</h3> `);
    if (template().groups.length > 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="overflow-x-auto rounded-lg"><table class="min-w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Description</th><th class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
      const each_array_1 = ensure_array_like(template().groups);
      for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
        let g = each_array_1[$$index_1];
        $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/group/${stringify(g.id)}`)}>${escape_html(g.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(g.name)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(g.description?.slice(0, 13) ?? "")}</td><td class="px-4 py-3 text-sm text-sat-l"><button type="button" class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors" title="Delete user from group"><i class="fa-solid fa-trash"></i></button></td></tr>`);
      }
      $$renderer2.push(`<!--]--></tbody></table></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<div class="p-4 text-muted-foreground">User is in no groups.</div>`);
    }
    $$renderer2.push(`<!--]--> `);
    ErrorAlert($$renderer2, { message: removeGroupError, class: "mt-3" });
    $$renderer2.push(`<!----></div></div>`);
  });
}
export {
  _page as default
};
