import { h as head, d as derived } from "../../../../../chunks/index2.js";
import { g as goto } from "../../../../../chunks/client.js";
import { D as DnsPacketBuilder, a as postOctalJson } from "../../../../../chunks/DnsPacketBuilder.js";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let { data } = $$props;
    const template = derived(() => data.template);
    async function submit(message) {
      const body = {
        probe_id: template().probe_id,
        src_mac: template().mac,
        src_addr: template().ip,
        dst_port: template().port,
        message
      };
      const res = await postOctalJson("/packet/create", body);
      await goto(`/packet/${res.id}`);
    }
    head("6kz3vb", $$renderer2, ($$renderer3) => {
      $$renderer3.title(($$renderer4) => {
        $$renderer4.push(`<title>edumdns - Create Packet</title>`);
      });
    });
    DnsPacketBuilder($$renderer2, {
      title: "Craft Packet",
      metadata: {
        probeId: template().probe_id,
        mac: template().mac,
        ip: template().ip,
        port: template().port
      },
      onSubmit: submit
    });
  });
}
export {
  _page as default
};
