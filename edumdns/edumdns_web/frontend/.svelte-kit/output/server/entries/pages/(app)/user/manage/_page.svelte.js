import { h as head, e as escape_html, a as attr, d as derived } from "../../../../../chunks/index2.js";
import "@sveltejs/kit/internal";
import "../../../../../chunks/exports.js";
import "../../../../../chunks/utils2.js";
import "@sveltejs/kit/internal/server";
import "../../../../../chunks/root.js";
import "../../../../../chunks/state.svelte.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const profileUser = derived(() => template().user.user);
    let profileName = "";
    let profileSurname = "";
    let profileEmail = "";
    head("1w6r2it", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Manage Profile</title>`);
      });
    });
    $$renderer2.push(`<div id="profile-update-fields" class="max-w-5xl mx-auto"><div id="user-mgmt-profile-form"><div class="rounded-lg border border-base bg-cards p-6 mt-6">`);
    if (template().oidc) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="w-full"><h3 class="text-sat-xl mb-4">User Information</h3> <div class="space-y-2 w-full"><div class="grid grid-cols-2 border-b border-base pb-1"><span class="font-bold text-acc text-left">Name:</span> <span class="text-sat-xl text-right">${escape_html(profileUser().name)}</span></div> <div class="grid grid-cols-2 border-b border-base pb-1"><span class="font-bold text-acc text-left">Surname:</span> <span class="text-sat-xl text-right">${escape_html(profileUser().surname)}</span></div> <div class="grid grid-cols-2 pb-1"><span class="font-bold text-acc text-left">Email:</span> <span class="text-sat-xl text-right">${escape_html(profileUser().email)}</span></div></div></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
      $$renderer2.push(`<form class="flex flex-col w-full items-center mx-auto p-4 space-y-4">`);
      {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--> <div class="flex flex-col w-full space-y-3 px-2"><div class="flex flex-col"><label for="profile-id-name" class="font-bold text-acc mb-1 text-left">Name</label> <input type="text" id="profile-id-name" name="name" placeholder="Name" class="p-3 rounded border border-base text-forms-input w-full"${attr("value", profileName)}/></div> <div class="flex flex-col"><label for="profile-id-surname" class="font-bold text-acc mb-1 text-left">Surname</label> <input type="text" id="profile-id-surname" name="surname" placeholder="Surname" class="p-3 rounded border border-base text-forms-input w-full"${attr("value", profileSurname)}/></div> <div class="flex flex-col"><label for="profile-id-email" class="font-bold text-acc mb-1 text-left">Email</label> <input type="email" id="profile-id-email" name="email" placeholder="Email" class="p-3 rounded border border-base text-forms-input w-full"${attr("value", profileEmail)}/></div></div> <div class="flex gap-4 mt-4"><button type="submit" class="bg-acc rounded-md p-2 text-button text-md shadow-md">Update Profile</button> <button type="button" class="bg-acc rounded-md p-2 text-button text-md shadow-md">Change Password</button></div></form>`);
    }
    $$renderer2.push(`<!--]--></div></div></div>`);
  });
}
export {
  _page as default
};
