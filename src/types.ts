// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { z } from 'zod';

/**
 * Custom error class for Shodan API errors.
 */
export class ShodanError extends Error {
  public readonly statusCode?: number;
  public readonly details?: unknown;

  constructor(message: string, statusCode?: number, details?: unknown) {
    super(message);
    this.name = 'ShodanError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

/**
 * Shodan client configuration schema.
 *
 * Supports two authentication patterns:
 *   - Direct (BYOK): Set SHODAN_API_KEY. Requests go directly to the Shodan API
 *     with the key injected as a query parameter.
 *   - Proxied (Hub):  Set SHODAN_BASE_URL (proxy endpoint) and SHODAN_AUTH_TOKEN
 *                     (Bearer token accepted by the proxy). The proxy injects the
 *                     real API key before forwarding to Shodan.
 *
 * The tool itself is agnostic to which pattern is in use.
 */
export const ShodanConfigSchema = z.object({
  apiKey: z
    .string()
    .optional()
    .describe('Shodan API key sent as ?key= query parameter (BYOK mode)'),
  baseUrl: z
    .string()
    .optional()
    .describe(
      'Override the Shodan API base URL. ' +
        'Defaults to https://api.shodan.io. ' +
        'Set this to a proxy endpoint to route requests through a backend.'
    ),
  cvedbUrl: z
    .string()
    .optional()
    .describe(
      'Override the Shodan CVEDB base URL. Defaults to https://cvedb.shodan.io. ' +
        'This endpoint is public and does not require authentication.'
    ),
  authToken: z
    .string()
    .optional()
    .describe(
      'Bearer token sent as Authorization header when using a proxy base URL. ' +
        'Ignored when apiKey is set.'
    ),
  timeout: z.number().optional().default(30000).describe('Request timeout in milliseconds'),
});

export type ShodanConfig = z.infer<typeof ShodanConfigSchema>;

/**
 * Options for creating a Shodan MCP server instance.
 */
export interface ServerCreationOptions {
  name: string;
  version: string;
  config: ShodanConfig;
  description?: string;
}
