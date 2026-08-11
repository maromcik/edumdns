import { h as head, a as attr, e as escape_html, c as ensure_array_like, s as stringify, d as derived } from "../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../chunks/exports.js";
import "../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../chunks/root.js";
import "../../../../chunks/state.svelte.js";
import { E as ErrorAlert } from "../../../../chunks/ErrorAlert.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    let filterName = "";
    let filterDescription = "";
    let newGroupName = "";
    let newGroupDescription = "";
    let formError = null;
    head("tm7cyd", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Groups</title>`);
      });
    });
    $$renderer2.push(`<div class="lg:w-3/4 w-full mx-auto mb-10 md:mb-5"><div class="flex flex-col justify-center items-center py-6"><h2 class="text-4xl font-bold text-sat-xl">Groups</h2></div> <div class="rounded-lg border border-base bg-cards p-6 mb-6"><h3 class="text-2xl font-semibold text-sat-l mb-4">New Group</h3> <form class="grid grid-cols-1 md:grid-cols-2 gap-4"><div class="flex flex-col"><label for="name" class="text-xs uppercase tracking-wide text-sat-l">Name</label> <input id="name" name="name" type="text" required="" class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter group name"${attr("value", newGroupName)}/></div> <div class="flex flex-col md:col-span-2"><label for="description" class="text-xs uppercase tracking-wide text-sat-m">Description</label> <textarea id="description" name="description" rows="3" class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Optional description">`);
    const $$body = escape_html(newGroupDescription);
    if ($$body) {
      $$renderer2.push(`${$$body}`);
    }
    $$renderer2.push(`</textarea></div> <div class="md:col-span-2"><button type="submit" class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-cards hover:bg-acc-xl transition-colors">Create Group</button></div></form> `);
    ErrorAlert($$renderer2, { message: formError, class: "mt-3" });
    $$renderer2.push(`<!----></div> <div class="overflow-x-auto rounded-lg border border-base bg-cards"><table class="w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Description</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr><tr><td class="px-4 py-2"></td><td class="px-4 py-2"><input type="text" id="filter-name"${attr("value", filterName)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-description"${attr("value", filterDescription)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2 flex gap-2"><button type="button" id="filter-button" class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button> <button type="button" id="reset-button" class="px-3 py-1 rounded-md text-button text-sm bg-acc-l hover:bg-muted/20 transition-colors">Reset</button></td></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
    const each_array = ensure_array_like(template().groups);
    for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
      let group = each_array[$$index];
      $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/group/${stringify(group.id)}`)} class="text-primary hover:underline">${escape_html(group.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(group.name)}</td><td class="px-4 py-3 text-sm text-sat-l">`);
      if (group.description) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`${escape_html(group.description)}`);
      } else {
        $$renderer2.push("<!--[-1-->");
        $$renderer2.push(`<span class="text-muted-foreground">—</span>`);
      }
      $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l"><button type="button" class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors" title="Delete group"><i class="fa-solid fa-trash"></i></button></td></tr>`);
    }
    $$renderer2.push(`<!--]--></tbody></table> `);
    if (template().groups.length === 0) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No groups found.</div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div></div>`);
  });
}
export {
  _page as default
};
