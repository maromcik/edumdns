import { h as head, d as derived } from "../../../../../../chunks/index2.js";
import { g as goto } from "../../../../../../chunks/client.js";
import { D as DnsPacketBuilder, p as parseServerMessage, a as postOctalJson } from "../../../../../../chunks/DnsPacketBuilder.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    const initial = derived(() => parseServerMessage(template().message) ?? void 0);
    async function submit(message) {
      const body = { packet_id: template().id, message };
      await postOctalJson("/packet/update-payload", body);
      await goto(`/packet/${template().id}`);
    }
    head("1uy4wsr", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Edit Packet Payload</title>`);
      });
    });
    DnsPacketBuilder($$renderer2, {
      title: "Edit Packet",
      metadata: {
        probeId: template().probe_id,
        mac: template().mac,
        ip: template().ip,
        port: template().port
      },
      initial: initial(),
      onSubmit: submit
    });
  });
}
export {
  _page as default
};
