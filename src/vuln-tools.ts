// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { z } from 'zod';
import { handleCveLookup, handleCpeLookup, handleCvesByProduct } from './handlers/vuln.js';

const CveLookupSchema = z.object({
  cve: z
    .string()
    .regex(/^CVE-\d{4}-\d{4,}$/i, 'Must be a valid CVE ID (e.g., CVE-2021-44228)')
    .describe('The CVE identifier to query (format: CVE-YYYY-NNNNN)'),
});

const CpeLookupSchema = z.object({
  product: z.string().describe('Product name to search for CPE entries'),
  count: z
    .boolean()
    .optional()
    .default(false)
    .describe('If true, returns only the total count of matching CPEs'),
  skip: z.number().optional().default(0).describe('Number of CPEs to skip (pagination)'),
  limit: z
    .number()
    .optional()
    .default(1000)
    .describe('Maximum number of CPEs to return (max 1000)'),
});

// Base object schema (without refinements) – used for .shape in tool registration
const CvesByProductBaseSchema = z.object({
  cpe23: z
    .string()
    .optional()
    .describe('CPE 2.3 identifier (format: cpe:2.3:part:vendor:product:version)'),
  product: z.string().optional().describe('Product name to search for CVEs'),
  count: z
    .boolean()
    .optional()
    .default(false)
    .describe('If true, returns only the total count of matching CVEs'),
  is_kev: z
    .boolean()
    .optional()
    .default(false)
    .describe('If true, returns only CVEs with the KEV flag set'),
  sort_by_epss: z
    .boolean()
    .optional()
    .default(false)
    .describe('If true, sorts CVEs by EPSS score in descending order'),
  skip: z.number().optional().default(0).describe('Number of CVEs to skip (pagination)'),
  limit: z.number().optional().default(1000).describe('Maximum CVEs to return (max 1000)'),
  start_date: z
    .string()
    .optional()
    .describe('Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)'),
  end_date: z
    .string()
    .optional()
    .describe('End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)'),
});

// Full schema with mutual-exclusion refinements – used for validation at parse time
const CvesByProductSchema = CvesByProductBaseSchema.refine(
  (data) => !(data.cpe23 && data.product),
  { message: 'Cannot specify both cpe23 and product. Use only one.' }
).refine((data) => data.cpe23 || data.product, {
  message: 'Must specify either cpe23 or product.',
});

/**
 * Register vulnerability intelligence tools on the MCP server.
 */
export async function registerVulnTools(
  server: McpServer,
  cvedbClient: AxiosInstance
): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'cve_lookup',
    "Query detailed vulnerability information from Shodan's CVEDB. Returns comprehensive CVE details " +
      'including CVSS scores (v2/v3), EPSS probability and ranking, KEV status, proposed mitigations, ' +
      'ransomware associations, and affected products (CPEs).',
    CveLookupSchema.shape,
    async (args: unknown) => {
      const { cve } = CveLookupSchema.parse(args);
      try {
        const result = await handleCveLookup(cvedbClient, cve);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );

  registerTool(
    'cpe_lookup',
    "Search for Common Platform Enumeration (CPE) entries by product name in Shodan's CVEDB. " +
      'Supports pagination and can return either full CPE details or just the total count.',
    CpeLookupSchema.shape,
    async (args: unknown) => {
      const { product, count, skip, limit } = CpeLookupSchema.parse(args);
      try {
        const result = await handleCpeLookup(cvedbClient, product, count ?? false, skip ?? 0, limit ?? 1000);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );

  registerTool(
    'cves_by_product',
    'Search for CVEs affecting specific products or CPEs. Supports filtering by KEV status, ' +
      'sorting by EPSS score, date ranges, and pagination. ' +
      'Provide either a product name or a CPE 2.3 identifier (not both).',
    CvesByProductBaseSchema.shape,
    async (args: unknown) => {
      const parsed = CvesByProductSchema.parse(args);
      try {
        const result = await handleCvesByProduct(cvedbClient, parsed);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
      }
    }
  );
}
