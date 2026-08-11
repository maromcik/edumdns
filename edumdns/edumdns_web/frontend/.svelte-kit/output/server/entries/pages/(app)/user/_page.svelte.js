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
      email: template().filters.email,
      id: template().filters.id,
      name: template().filters.name,
      surname: template().filters.surname,
      admin: template().filters.admin,
      disabled: template().filters.disabled
    }));
    let filterId = "";
    let filterEmail = "";
    let filterName = "";
    let filterSurname = "";
    let filterAdmin = "";
    let filterDisabled = "";
    async function runSearch() {
      await goto(`/user${buildQuery({
        id: filterId.trim(),
        email: filterEmail.trim(),
        name: filterName.trim(),
        surname: filterSurname.trim(),
        admin: filterAdmin,
        disabled: filterDisabled
      })}`);
    }
    let newEmail = "";
    let newName = "";
    let newSurname = "";
    let newPassword = "";
    let newConfirmPassword = "";
    let newAdmin = false;
    let formError = null;
    head("x5fum9", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Users</title>`);
      });
    });
    if (data.user.user.admin) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="lg:w-3/4 w-full mx-auto mb-10 md:mb-5"><div class="flex flex-col justify-center items-center py-6"><h2 class="text-4xl font-bold text-sat-xl">Users</h2></div> <div class="rounded-lg border border-base bg-cards p-6 mb-6"><h3 class="text-2xl font-semibold text-sat-l mb-4">New User</h3> <form class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-3 gap-4"><div class="flex flex-col"><label for="email" class="text-xs uppercase tracking-wide text-sat-l">Email</label> <input id="email" name="email" type="email" required="" class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter email"${attr("value", newEmail)}/></div> <div class="flex flex-col"><label for="name" class="text-xs uppercase tracking-wide text-sat-l">Name</label> <input id="name" name="name" type="text" required="" class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter name"${attr("value", newName)}/></div> <div class="flex flex-col"><label for="surname" class="text-xs uppercase tracking-wide text-sat-l">Surname</label> <input id="surname" name="surname" type="text" required="" class="mt-1 rounded-md border border-base px-3 py-2 text-forms-input focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter surname"${attr("value", newSurname)}/></div> <div class="flex flex-col"><label for="password" class="text-xs uppercase tracking-wide text-sat-l">Password</label> <input id="password" name="password" type="password" required="" class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter password"${attr("value", newPassword)}/></div> <div class="flex flex-col"><label for="confirm_password" class="text-xs uppercase tracking-wide text-sat-l">Confirm Password</label> <input id="confirm_password" name="confirm_password" type="password" required="" class="mt-1 rounded-md border border-base text-forms-input px-3 py-2 focus:outline-none focus:ring-2 focus:ring-acc" placeholder="Enter password again"${attr("value", newConfirmPassword)}/></div> <div class="flex items-center mt-1"><input id="admin" name="admin" type="checkbox" value="true" class="h-4 w-4 rounded border-base text-forms-input text-acc focus:ring-2 focus:ring-acc"${attr("checked", newAdmin, true)}/> <label for="admin" class="ml-2 text-xs uppercase tracking-wide text-sat-l">Admin</label></div> <div class="md:col-span-2"><button type="submit" class="inline-flex items-center rounded-md text-button bg-acc px-4 py-2 text-sm font-medium hover:bg-acc-xl transition-colors">Create User</button></div></form> `);
      ErrorAlert($$renderer2, { message: formError, class: "mt-3" });
      $$renderer2.push(`<!----></div> <div class="overflow-x-auto rounded-lg border border-base bg-cards"><table class="w-full divide-y divide-base"><thead class="bg-muted/10"><tr><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">ID</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Email</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Name</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Surname</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Admin</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Disabled</th><th scope="col" class="px-4 py-3 text-left text-xs text-sat-l font-medium uppercase tracking-wider text-muted-foreground">Actions</th></tr><tr><td class="px-4 py-2"><input type="text" id="filter-id"${attr("value", filterId)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-email"${attr("value", filterEmail)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-name"${attr("value", filterName)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2"><input type="text" id="filter-surname"${attr("value", filterSurname)} class="w-full rounded-md border border-base px-2 py-1 text-sm"/></td><td class="px-4 py-2">`);
      $$renderer2.select(
        {
          id: "filter-admin",
          class: "w-full rounded-md border border-base px-2 py-1 text-sm",
          value: filterAdmin,
          onchange: runSearch
        },
        ($$renderer3) => {
          $$renderer3.option({ value: "" }, ($$renderer4) => {
            $$renderer4.push(`All`);
          });
          $$renderer3.option({ value: "true" }, ($$renderer4) => {
            $$renderer4.push(`Admin`);
          });
          $$renderer3.option({ value: "false" }, ($$renderer4) => {
            $$renderer4.push(`Not Admin`);
          });
        }
      );
      $$renderer2.push(`</td><td class="px-4 py-2">`);
      $$renderer2.select(
        {
          id: "filter-disabled",
          class: "w-full rounded-md border border-base px-2 py-1 text-sm",
          value: filterDisabled,
          onchange: runSearch
        },
        ($$renderer3) => {
          $$renderer3.option({ value: "" }, ($$renderer4) => {
            $$renderer4.push(`All`);
          });
          $$renderer3.option({ value: "true" }, ($$renderer4) => {
            $$renderer4.push(`Disabled`);
          });
          $$renderer3.option({ value: "false" }, ($$renderer4) => {
            $$renderer4.push(`Enabled`);
          });
        }
      );
      $$renderer2.push(`</td><td class="px-4 py-2 flex gap-2"><button type="button" id="filter-button" class="px-3 py-1 rounded-md bg-acc text-sm bg-primary text-button hover:bg-primary/90 transition-colors">Search</button> <button type="button" id="reset-button" class="px-3 py-1 rounded-md text-sm bg-acc-l text-button hover:bg-muted/20 transition-colors">Reset</button></td></tr></thead><tbody class="divide-y divide-base"><!--[-->`);
      const each_array = ensure_array_like(template().users);
      for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
        let user = each_array[$$index];
        $$renderer2.push(`<tr class="cursor-pointer rounded-lg bg-table transition-colors"><td class="px-4 py-3 font-mono text-sm text-sat-l"><a${attr("href", `/user/${stringify(user.id)}`)} class="text-primary hover:underline">${escape_html(user.id)}</a></td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(user.email)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(user.name)}</td><td class="px-4 py-3 text-sm text-sat-l">${escape_html(user.surname)}</td><td class="px-4 py-3 text-sm">`);
        if (user.admin) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">Yes</span>`);
        } else {
          $$renderer2.push("<!--[-1-->");
          $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">No</span>`);
        }
        $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm">`);
        if (!user.disabled) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">No</span>`);
        } else {
          $$renderer2.push("<!--[-1-->");
          $$renderer2.push(`<span class="inline-flex items-center rounded-md bg-yellow-100 px-2 py-0.5 text-xs font-medium text-yellow-800">Yes</span>`);
        }
        $$renderer2.push(`<!--]--></td><td class="px-4 py-3 text-sm text-sat-l"><button type="button" class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors" title="Delete user"><i class="fa-solid fa-trash"></i></button></td></tr>`);
      }
      $$renderer2.push(`<!--]--></tbody></table> `);
      if (template().users.length === 0) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<div class="p-6 text-center text-muted-foreground">No users found.</div>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></div> `);
      Pagination($$renderer2, {
        pageInfo: template().page_info,
        basePath: "/user",
        filters: pageFilters()
      });
      $$renderer2.push(`<!----></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      ErrorAlert($$renderer2, { message: "You must be an administrator to view users." });
    }
    $$renderer2.push(`<!--]-->`);
  });
}
export {
  _page as default
};
