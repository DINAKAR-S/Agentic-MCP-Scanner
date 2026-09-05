// The same server as demo/vulnerable-2026/server.ts with each defect fixed.
// Every finding the scanner reports on this file is a false positive.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";

function createServer(): McpServer {
  const server = new McpServer({ name: "demo-2026-fixed", version: "0.0.0" });

  server.registerTool("add", {
    title: "Add",
    description: "Adds two numbers and returns the sum.",
    inputSchema: {},
  }, async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] }));

  server.registerTool("weather", {
    title: "Weather",
    description: "Returns the current weather for a city.",
    inputSchema: {},
  }, async () => ({ content: [{ type: "text", text: "sunny" }] }));

  server.registerTool("lookup", {
    title: "Lookup",
    description: "Look up a record by its identifier.",
    inputSchema: {},
  }, async () => ({ content: [{ type: "text", text: "ok" }] }));

  return server;
}

const app = express();
app.post("/mcp", async (req, res) => {
  // One server and one transport per request: nothing is shared between clients.
  const server = createServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableDnsRebindingProtection: true,
    allowedHosts: ["127.0.0.1:3000", "localhost:3000"],
  });
  res.on("close", () => { transport.close(); server.close(); });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(3000, "127.0.0.1");
