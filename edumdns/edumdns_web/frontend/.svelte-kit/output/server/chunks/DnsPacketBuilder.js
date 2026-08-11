import "clsx";
import "@sveltejs/kit/internal";
import "./exports.js";
import "./utils2.js";
import "@sveltejs/kit/internal/server";
import "./root.js";
import "./state.svelte.js";
import { A as ApiError } from "./api.js";
import { e as escape_html, a as attr, c as ensure_array_like, b as attr_class, s as stringify } from "./index2.js";
import { E as ErrorAlert } from "./ErrorAlert.js";
let rowKey = 0;
function newQueryRow(init) {
  return {
    key: ++rowKey,
    name: init?.name ?? "",
    queryType: init?.queryType ?? "A",
    queryClass: init?.queryClass ?? "IN"
  };
}
function newRecordRow(init) {
  return {
    key: ++rowKey,
    name: init?.name ?? "",
    dnsClass: init?.dnsClass ?? "IN",
    ttl: init?.ttl ?? 300,
    recordType: init?.recordType ?? "A",
    rdata: init?.rdata ?? "",
    srvPriority: init?.srvPriority ?? null,
    srvWeight: init?.srvWeight ?? null,
    srvPort: init?.srvPort ?? null,
    srvTarget: init?.srvTarget ?? ""
  };
}
function defaultBuilderState() {
  return {
    header: { id: 0, messageType: "Query", opCode: "Query", responseCode: "NoError" },
    queries: [],
    answers: [],
    additionals: []
  };
}
function serverClass(value) {
  return typeof value === "string" && value ? value : "IN";
}
function txtToString(value) {
  let parts = [];
  if (Array.isArray(value)) {
    parts = value;
  } else if (value && typeof value === "object") {
    const txtData = value.txt_data;
    if (Array.isArray(txtData)) parts = txtData;
  }
  const decoder = new TextDecoder();
  return parts.map((arr) => Array.isArray(arr) ? decoder.decode(new Uint8Array(arr)) : String(arr)).join(", ");
}
function recordRowFromServer(rr) {
  const rdata = rr.rdata ?? {};
  const type = Object.keys(rdata)[0] ?? "A";
  const value = rdata[type];
  const row = newRecordRow({
    name: rr.name_labels ?? "",
    dnsClass: serverClass(rr.dns_class),
    ttl: rr.ttl ?? 300,
    recordType: type
  });
  if (type === "TXT") {
    row.rdata = txtToString(value);
  } else if (type === "SRV") {
    const srv = value ?? {};
    row.srvPriority = srv.priority ?? 0;
    row.srvWeight = srv.weight ?? 0;
    row.srvPort = srv.port ?? 0;
    row.srvTarget = srv.target ?? "";
  } else {
    row.rdata = value == null ? "" : String(value);
  }
  return row;
}
function parseServerMessage(raw) {
  const decoded = octalToUtf8(raw);
  if (!decoded || decoded.trim().length === 0) return null;
  let msg;
  try {
    msg = JSON.parse(decoded);
  } catch {
    return null;
  }
  const state = defaultBuilderState();
  if (msg.header) {
    state.header.id = msg.header.id ?? 0;
    state.header.messageType = msg.header.message_type ?? "Query";
    state.header.opCode = msg.header.op_code ?? "Query";
    state.header.responseCode = msg.header.response_code ?? "NoError";
  }
  if (Array.isArray(msg.queries)) {
    state.queries = msg.queries.filter((q) => q != null).map(
      (q) => newQueryRow({
        name: q.name ?? "",
        queryType: q.query_type ?? "A",
        queryClass: serverClass(q.query_class)
      })
    );
  }
  if (Array.isArray(msg.answers)) {
    state.answers = msg.answers.filter((rr) => rr != null).map(recordRowFromServer);
  }
  if (Array.isArray(msg.additionals)) {
    state.additionals = msg.additionals.filter((rr) => rr != null).map(recordRowFromServer);
  }
  return state;
}
function utf8ToOctal(str) {
  if (!str) return str;
  const bytes = new TextEncoder().encode(str);
  let out = "";
  for (const b of bytes) {
    const ch = String.fromCharCode(b);
    if (b >= 48 && b <= 57 || // 0-9
    b >= 65 && b <= 90 || // A-Z
    b >= 97 && b <= 122 || // a-z
    ch === "-" || ch === "." || ch === "{" || ch === "[" || ch === "(" || ch === "}" || ch === "]" || ch === ")" || ch === "," || ch === '"' || ch === "'" || ch === ":" || ch === "_" || ch === "/") {
      out += ch;
    } else {
      out += "\\\\" + b.toString(8).padStart(3, "0");
    }
  }
  return out;
}
function octalToUtf8(str) {
  if (!str) return str;
  const bytes = [];
  let i = 0;
  while (i < str.length) {
    if (str[i] === "\\" && i + 3 < str.length && /^[0-7]{3}$/.test(str.slice(i + 1, i + 4))) {
      bytes.push(parseInt(str.slice(i + 1, i + 4), 8));
      i += 4;
    } else {
      const encoded = new TextEncoder().encode(str[i]);
      bytes.push(...encoded);
      i += 1;
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}
async function postOctalJson(path, payload) {
  const res = await fetch(`/api${path}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: utf8ToOctal(JSON.stringify(payload))
  });
  if (res.status === 401) ;
  if (!res.ok) {
    let generic = {
      code: res.status,
      status_code: res.statusText,
      description: res.statusText
    };
    try {
      generic = { ...generic, ...await res.json() };
    } catch {
    }
    throw new ApiError(generic);
  }
  if (res.status === 204) return void 0;
  const text = await res.text();
  return text ? JSON.parse(text) : void 0;
}
function DnsPacketBuilder($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { title, metadata, initial = null, onSubmit } = $$props;
    let headerId = 0;
    let messageType = "Query";
    let opCode = "Query";
    let responseCode = "NoError";
    let queries = [];
    let answers = [];
    let additionals = [];
    let submitting = false;
    let submitError = null;
    function recordRows($$renderer3, kind, rows) {
      $$renderer3.push(`<!--[-->`);
      const each_array = ensure_array_like(rows);
      for (let $$index = 0, $$length = each_array.length; $$index < $$length; $$index++) {
        let row = each_array[$$index];
        $$renderer3.push(`<div${attr_class(`${stringify(kind)}-row border-gray-500 dark:border-gray-300 border-2 rounded p-3`)}><div class="grid grid-cols-1 md:grid-cols-6 gap-2 items-start"><input type="text" placeholder="name_labels (example.com.)"${attr_class(`${stringify(kind)}-name md:col-span-2 rounded border px-2 py-1 w-full`)}${attr("value", row.name)}/> <input type="text" placeholder="class (IN)"${attr_class(`${stringify(kind)}-class w-full md:w-20 rounded border px-2 py-1`)}${attr("value", row.dnsClass)}/> <input type="number" placeholder="ttl"${attr_class(`${stringify(kind)}-ttl w-full md:w-24 rounded border px-2 py-1`)}${attr("value", row.ttl)}/> `);
        $$renderer3.select(
          {
            class: `${stringify(kind)}-type w-full md:w-24 rounded bg-gray-50 border px-2 py-1`,
            value: row.recordType
          },
          ($$renderer4) => {
            $$renderer4.option({ value: "A" }, ($$renderer5) => {
              $$renderer5.push(`A`);
            });
            $$renderer4.option({ value: "AAAA" }, ($$renderer5) => {
              $$renderer5.push(`AAAA`);
            });
            $$renderer4.option({ value: "CNAME" }, ($$renderer5) => {
              $$renderer5.push(`CNAME`);
            });
            $$renderer4.option({ value: "MX" }, ($$renderer5) => {
              $$renderer5.push(`MX`);
            });
            $$renderer4.option({ value: "TXT" }, ($$renderer5) => {
              $$renderer5.push(`TXT`);
            });
            $$renderer4.option({ value: "PTR" }, ($$renderer5) => {
              $$renderer5.push(`PTR`);
            });
            $$renderer4.option({ value: "SRV" }, ($$renderer5) => {
              $$renderer5.push(`SRV`);
            });
          }
        );
        $$renderer3.push(` <div${attr_class(`${stringify(kind)}-rdata-wrap col-span-1 md:col-span-6 mt-2`, void 0, { "hidden": row.recordType === "SRV" })}><input type="text" placeholder="rdata (e.g. 1.2.3.4, text, or PTR target)"${attr_class(`${stringify(kind)}-rdata w-full rounded border px-2 py-1`)}${attr("value", row.rdata)}/></div> <div${attr_class(`${stringify(kind)}-srv-wrap col-span-1 md:col-span-6 mt-2`, void 0, { "hidden": row.recordType !== "SRV" })}><div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 items-center"><input type="number" min="0" max="65535" placeholder="priority"${attr_class(`${stringify(kind)}-srv-priority rounded border px-2 py-1`)}${attr("value", row.srvPriority)}/> <input type="number" min="0" max="65535" placeholder="weight"${attr_class(`${stringify(kind)}-srv-weight rounded border px-2 py-1`)}${attr("value", row.srvWeight)}/> <input type="number" min="0" max="65535" placeholder="port"${attr_class(`${stringify(kind)}-srv-port rounded border px-2 py-1`)}${attr("value", row.srvPort)}/> <input type="text" placeholder="target (example.com.)"${attr_class(`${stringify(kind)}-srv-target rounded border px-2 py-1`)}${attr("value", row.srvTarget)}/></div></div> <div class="col-span-1 md:col-span-6 mt-2 flex justify-end"><button type="button" title="Remove record" class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"><i class="fa-solid fa-trash"></i></button></div></div></div>`);
      }
      $$renderer3.push(`<!--]-->`);
    }
    $$renderer2.push(`<div class="max-w-7xl mx-auto px-4 sm:px-8"><form class="space-y-6 bg-cards shadow-md rounded px-8 pt-6 pb-8"><h2 class="text-xl text-sat-l font-bold text-center mb-4">${escape_html(title)}</h2> <div class="grid grid-cols-2 gap-4"><div><label class="block text-xs text-forms uppercase mb-1" for="meta-probe-id">Probe ID</label> <div class="p-2 bg-forms-fields rounded border break-all" id="meta-probe-id"><code class="text-code">${escape_html(metadata.probeId)}</code></div></div> <div><label class="block text-xs text-forms uppercase mb-1" for="meta-src-mac">Source MAC</label> <div class="p-2 rounded border bg-forms-fields break-all" id="meta-src-mac"><code class="text-code">${escape_html(metadata.mac)}</code></div></div> <div><label class="block text-xs text-forms uppercase mb-1" for="meta-src-ip">Source IP</label> <div class="p-2 rounded border bg-forms-fields break-all" id="meta-src-ip"><code class="text-code">${escape_html(metadata.ip)}</code></div></div> <div><label class="block text-xs text-forms uppercase mb-1" for="meta-dst-port">Dest Port</label> <div class="p-2 rounded border bg-forms-fields break-all" id="meta-dst-port"><code class="text-code">${escape_html(metadata.port)}</code></div></div></div> <fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4"><legend class="text-lg text-sat-xl font-semibold">DNS Header</legend> <div class="grid grid-cols-2 gap-4"><div><label class="block text-xs text-forms uppercase mb-1" for="header-message-type">Message Type</label> `);
    $$renderer2.select(
      {
        id: "header-message-type",
        class: "w-full rounded border bg-gray-50 px-2 py-1",
        value: messageType
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "Query" }, ($$renderer4) => {
          $$renderer4.push(`Query`);
        });
        $$renderer3.option({ value: "Response" }, ($$renderer4) => {
          $$renderer4.push(`Response`);
        });
      }
    );
    $$renderer2.push(`</div> <div><label class="block text-xs text-forms uppercase mb-1" for="header-op-code">Op Code</label> `);
    $$renderer2.select(
      {
        id: "header-op-code",
        class: "w-full bg-gray-50 rounded border px-2 py-1",
        value: opCode
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "Query" }, ($$renderer4) => {
          $$renderer4.push(`Query`);
        });
        $$renderer3.option({ value: "IQuery" }, ($$renderer4) => {
          $$renderer4.push(`IQuery`);
        });
        $$renderer3.option({ value: "Status" }, ($$renderer4) => {
          $$renderer4.push(`Status`);
        });
      }
    );
    $$renderer2.push(`</div> <div><label class="block text-xs text-forms uppercase mb-1" for="header-response-code">Response Code</label> `);
    $$renderer2.select(
      {
        id: "header-response-code",
        class: "w-full bg-gray-50 rounded border px-2 py-1",
        value: responseCode
      },
      ($$renderer3) => {
        $$renderer3.option({ value: "NoError" }, ($$renderer4) => {
          $$renderer4.push(`NoError`);
        });
        $$renderer3.option({ value: "FormErr" }, ($$renderer4) => {
          $$renderer4.push(`FormErr`);
        });
        $$renderer3.option({ value: "ServFail" }, ($$renderer4) => {
          $$renderer4.push(`ServFail`);
        });
        $$renderer3.option({ value: "NXDomain" }, ($$renderer4) => {
          $$renderer4.push(`NXDomain`);
        });
      }
    );
    $$renderer2.push(`</div> <div><label class="block text-xs text-forms uppercase mb-1" for="header-id">ID</label> <input id="header-id" type="number" min="0" max="65535" class="w-full text-forms-input bg-gray-50 rounded border px-2 py-1"${attr("value", headerId)}/></div></div></fieldset> <fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4"><legend class="text-lg text-sat-xl font-semibold">Queries</legend> <div class="space-y-3"><!--[-->`);
    const each_array_1 = ensure_array_like(queries);
    for (let $$index_1 = 0, $$length = each_array_1.length; $$index_1 < $$length; $$index_1++) {
      let row = each_array_1[$$index_1];
      $$renderer2.push(`<div class="query-row border-gray-500 dark:border-gray-300 border-2 dark:border rounded p-3 gap-2 items-center"><input type="text" placeholder="name (example.com.)" class="query-name flex-1 rounded border px-2 py-1"${attr("value", row.name)}/> `);
      $$renderer2.select(
        {
          class: "query-type w-28 rounded bg-gray-50 border px-2 py-1",
          value: row.queryType
        },
        ($$renderer3) => {
          $$renderer3.option({ value: "A" }, ($$renderer4) => {
            $$renderer4.push(`A`);
          });
          $$renderer3.option({ value: "AAAA" }, ($$renderer4) => {
            $$renderer4.push(`AAAA`);
          });
          $$renderer3.option({ value: "ANY" }, ($$renderer4) => {
            $$renderer4.push(`ANY`);
          });
          $$renderer3.option({ value: "CNAME" }, ($$renderer4) => {
            $$renderer4.push(`CNAME`);
          });
          $$renderer3.option({ value: "MX" }, ($$renderer4) => {
            $$renderer4.push(`MX`);
          });
          $$renderer3.option({ value: "TXT" }, ($$renderer4) => {
            $$renderer4.push(`TXT`);
          });
          $$renderer3.option({ value: "PTR" }, ($$renderer4) => {
            $$renderer4.push(`PTR`);
          });
          $$renderer3.option({ value: "SRV" }, ($$renderer4) => {
            $$renderer4.push(`SRV`);
          });
        }
      );
      $$renderer2.push(` <input type="text" placeholder="class (IN)" class="text-forms-input query-class w-20 rounded border px-2 py-1 mt-2"${attr("value", row.queryClass)}/> <button type="button" title="Remove query" class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"><i class="fa-solid fa-trash"></i></button></div>`);
    }
    $$renderer2.push(`<!--]--></div> <div class="mt-2 flex gap-2"><button type="button" class="bg-acc text-button px-3 py-1 rounded">+ Query</button></div></fieldset> <fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4"><legend class="text-lg text-forms font-semibold">Answers</legend> <div class="space-y-3">`);
    recordRows($$renderer2, "answer", answers);
    $$renderer2.push(`<!----></div> <div class="mt-2 flex gap-2"><button type="button" class="bg-acc text-button px-3 py-1 rounded">+ Answer</button></div></fieldset> <fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4"><legend class="text-lg text-forms font-semibold">Additionals</legend> <div class="space-y-3">`);
    recordRows($$renderer2, "additional", additionals);
    $$renderer2.push(`<!----></div> <div class="mt-2 flex gap-2"><button type="button" class="bg-acc text-button px-3 py-1 rounded">+ Additional</button></div></fieldset> <div class="flex justify-end gap-3"><button type="button" class="px-4 py-2 text-forms rounded border">Preview JSON</button> <button type="submit"${attr("disabled", submitting, true)} class="bg-acc hover:bg-acc-l text-button px-6 py-2 rounded">Send Packet</button></div> `);
    ErrorAlert($$renderer2, { message: submitError });
    $$renderer2.push(`<!----></form> `);
    {
      $$renderer2.push("<!--[-1-->");
    }
    $$renderer2.push(`<!--]--></div>`);
  });
}
export {
  DnsPacketBuilder as D,
  postOctalJson as a,
  parseServerMessage as p
};
