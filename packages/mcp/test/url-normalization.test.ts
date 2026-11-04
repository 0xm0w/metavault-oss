import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { expect, it } from "vitest";
import { createMetavaultMcpServer } from "../src/server.js";
it("normalizes arbitrarily long slash suffix with linear scan", async () => {
  let called = "";
  const server = createMetavaultMcpServer({daemonUrl: "http://127.0.0.1:7077" + "/".repeat(100000), fetchFn: (input) => {called=typeof input === "string" ? input : input instanceof URL ? input.href : input.url;return Promise.resolve(new Response(JSON.stringify({aliases:[]})));}});
  const client = new Client({name:"synthetic-url-test",version:"1"});
  const [a,b]=InMemoryTransport.createLinkedPair();
  await server.connect(a);await client.connect(b);
  try {await client.callTool({name:"list_aliases",arguments:{}});expect(called).toBe("http://127.0.0.1:7077/aliases");}
  finally {await client.close();await server.close();}
});
