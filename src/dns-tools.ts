// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { z } from 'zod';
import { handleDnsLookup, handleReverseDnsLookup } from './handlers/dns.js';

const DnsLookupSchema = z.object({
  hostnames: z.array(z.string()).describe('List of hostnames to resolve to IP addresses'),
});

const ReverseDnsLookupSchema = z.object({
  ips: z.array(z.string()).describe('List of IP addresses for reverse DNS lookup'),
});

/**
 * Register DNS resolution tools on the MCP server.
 */
export async function registerDnsTools(server: McpServer, client: AxiosInstance): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'dns_lookup',
    "Resolve domain names to IP addresses using Shodan's DNS service. " +
      'Supports batch resolution of multiple hostnames in a single query.',
    DnsLookupSchema.shape,
    async (args: unknown) => {
      const { hostnames } = DnsLookupSchema.parse(args);
      try {
        const result = await handleDnsLookup(client, hostnames);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );

  registerTool(
    'reverse_dns_lookup',
    'Perform reverse DNS lookups to find hostnames associated with IP addresses. ' +
      'Supports batch lookups of multiple IP addresses in a single query.',
    ReverseDnsLookupSchema.shape,
    async (args: unknown) => {
      const { ips } = ReverseDnsLookupSchema.parse(args);
      try {
        const result = await handleReverseDnsLookup(client, ips);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );
}
