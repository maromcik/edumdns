import { a as attr, c as ensure_array_like, e as escape_html, d as derived } from "./index2.js";
import { b as buildQuery } from "./api.js";
function Pagination($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { pageInfo, basePath, filters = {} } = $$props;
    function href(page) {
      return `${basePath}${buildQuery({ ...filters, page })}`;
    }
    const pages = derived(() => {
      const out = [];
      for (const p2 of [
        pageInfo.page - 2,
        pageInfo.page - 1,
        pageInfo.page,
        pageInfo.page + 1,
        pageInfo.page + 2
      ]) {
        if (p2 >= 1 && p2 <= pageInfo.total_pages) out.push(p2);
      }
      return out;
    });
    if (pageInfo.total_pages > 1) {
      $$renderer2.push("<!--[0-->");
      $$renderer2.push(`<div class="flex flex-wrap justify-center items-center mt-6 gap-2">`);
      if (pageInfo.page > 1) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<a${attr("href", href(pageInfo.page - 1))} class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors">Prev</a>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--> `);
      if (pageInfo.page > 4) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<a${attr("href", href(1))} class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors">1</a>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--> `);
      if (pageInfo.page > 4) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="px-3 py-1 rounded-md border border-base text-sm">...</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--> <!--[-->`);
      const each_array = ensure_array_like(pages());
      for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
        let p = each_array[$$index];
        if (p === pageInfo.page) {
          $$renderer2.push("<!--[0-->");
          $$renderer2.push(`<span class="px-3 py-1 rounded-md bg-primary text-white text-sm">${escape_html(p)}</span>`);
        } else {
          $$renderer2.push("<!--[-1-->");
          $$renderer2.push(`<a${attr("href", href(p))} class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors">${escape_html(p)}</a>`);
        }
        $$renderer2.push(`<!--]-->`);
      }
      $$renderer2.push(`<!--]--> `);
      if (pageInfo.page < pageInfo.total_pages - 3) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<span class="px-3 py-1 rounded-md border border-base text-sm">...</span>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--> `);
      if (pageInfo.page < pageInfo.total_pages - 2) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<a${attr("href", href(pageInfo.total_pages))} class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors">${escape_html(pageInfo.total_pages)}</a>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--> `);
      if (pageInfo.page < pageInfo.total_pages) {
        $$renderer2.push("<!--[0-->");
        $$renderer2.push(`<a${attr("href", href(pageInfo.page + 1))} class="px-3 py-1 rounded-md border border-base text-sm hover:bg-muted/20 transition-colors">Next</a>`);
      } else {
        $$renderer2.push("<!--[-1-->");
      }
      $$renderer2.push(`<!--]--></div>`);
    } else {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]-->`);
  });
}
export {
  Pagination as P
};
