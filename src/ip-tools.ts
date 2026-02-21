// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { z } from 'zod';
import { handleIpLookup, handleShodanSearch } from './handlers/ip.js';

const IpLookupSchema = z.object({
  ip: z.string().describe('The IP address to look up'),
});

const ShodanSearchSchema = z.object({
  query: z.string().describe('Shodan search query'),
  max_results: z
    .number()
    .optional()
    .default(10)
    .describe('Maximum number of results to return (default: 10)'),
});

/**
 * Register IP address and device search tools on the MCP server.
 */
export async function registerIpTools(server: McpServer, client: AxiosInstance): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'ip_lookup',
    'Retrieve comprehensive information about an IP address from Shodan, including geolocation, ' +
      'open ports, running services, SSL certificates, hostnames, and cloud provider details.',
    IpLookupSchema.shape,
    async (args: unknown) => {
      const { ip } = IpLookupSchema.parse(args);
      try {
        const result = await handleIpLookup(client, ip);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );

  registerTool(
    'shodan_search',
    "Search Shodan's database of internet-connected devices. Returns detailed information about " +
      'matching devices including services, vulnerabilities, and geographic distribution. ' +
      'Supports advanced search filters and returns country-based statistics.',
    ShodanSearchSchema.shape,
    async (args: unknown) => {
      const { query, max_results } = ShodanSearchSchema.parse(args);
      try {
        const result = await handleShodanSearch(client, query, max_results ?? 10);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );
}
