#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { randomUUID } from 'crypto';
import {
  ShodanConfig,
  ShodanConfigSchema,
  ServerCreationOptions,
} from './src/types.js';
import { createShodanClient, createCvedbClient } from './src/utils/api.js';
import { registerIpTools } from './src/ip-tools.js';
import { registerDnsTools } from './src/dns-tools.js';
import { registerVulnTools } from './src/vuln-tools.js';

/**
 * Create and configure a Shodan MCP server instance with all tool modules registered.
 *
 * Auth note: the server starts without credentials and gracefully surfaces
 * 401/403 errors as tool errors rather than crashing on startup.
 */
export async function createShodanMcpServer(
  options: ServerCreationOptions
): Promise<McpServer> {
  const { name, version, config, description } = options;

  const validatedConfig = ShodanConfigSchema.parse(config);
  const shodanClient = createShodanClient(validatedConfig);
  const cvedbClient = createCvedbClient(validatedConfig);

  const server = new McpServer({
    name,
    version,
    ...(description ? { description } : {}),
  });

  await Promise.all([
    registerIpTools(server, shodanClient),
    registerDnsTools(server, shodanClient),
    registerVulnTools(server, cvedbClient),
  ]);

  return server;
}

// Main entry point
async function main(): Promise<void> {
  const config: ShodanConfig = {
    apiKey: process.env.SHODAN_API_KEY,
    baseUrl: process.env.SHODAN_BASE_URL,
    cvedbUrl: process.env.SHODAN_CVEDB_URL,
    authToken: process.env.SHODAN_AUTH_TOKEN,
    timeout: parseInt(process.env.SHODAN_TIMEOUT ?? '30000', 10),
  };

  const SERVER_NAME = 'shodan-mcp-server';
  const SERVER_VERSION = '1.0.0';
  const SERVER_DESCRIPTION =
    'Shodan MCP Server – network reconnaissance, DNS operations, and vulnerability intelligence';

  const useHttp = process.env.MCP_TRANSPORT === 'http';
  const httpPort = parseInt(process.env.MCP_HTTP_PORT ?? '3001', 10);
  const httpHost = process.env.MCP_HTTP_HOST ?? 'localhost';

  if (useHttp) {
    process.stderr.write(
      `Starting Shodan MCP Server in HTTP mode on ${httpHost}:${httpPort}\n`
    );

    const app = express();
    app.use(express.json());

    const transports = new Map<string, StreamableHTTPServerTransport>();

    app.get('/health', (_req, res) => {
      res.json({ status: 'ok', transport: 'streamable-http' });
    });

    app.post('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      try {
        let transport: StreamableHTTPServerTransport;

        if (sessionId !== undefined && transports.has(sessionId)) {
          transport = transports.get(sessionId)!;
        } else {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: async (newSessionId: string) => {
              transports.set(newSessionId, transport);
              process.stderr.write(`MCP session initialized: ${newSessionId}\n`);
            },
            onsessionclosed: async (closedSessionId: string) => {
              transports.delete(closedSessionId);
              process.stderr.write(`MCP session closed: ${closedSessionId}\n`);
            },
          });

          const server = await createShodanMcpServer({
            name: SERVER_NAME,
            version: SERVER_VERSION,
            config,
            description: SERVER_DESCRIPTION,
          });

          await server.connect(transport);
        }

        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        process.stderr.write(`Error handling MCP request: ${error}\n`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          });
        }
      }
    });

    app.get('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      if (sessionId === undefined || !transports.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Invalid or missing session ID' },
          id: null,
        });
        return;
      }

      try {
        const transport = transports.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (error) {
        process.stderr.write(`Error handling SSE stream: ${error}\n`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Failed to establish SSE stream' },
            id: null,
          });
        }
      }
    });

    app.listen(httpPort, httpHost, () => {
      process.stderr.write(
        `Shodan MCP Server (HTTP mode) started on http://${httpHost}:${httpPort}\n`
      );
    });

    process.on('SIGINT', async () => {
      for (const [, transport] of transports.entries()) {
        await transport.close();
      }
      process.exit(0);
    });
  } else {
    // Stdio mode (default) – for local MCP client integrations
    process.stderr.write('Starting Shodan MCP Server in Stdio mode\n');

    const server = await createShodanMcpServer({
      name: SERVER_NAME,
      version: SERVER_VERSION,
      config,
      description: SERVER_DESCRIPTION,
    });

    const transport = new StdioServerTransport();
    await server.connect(transport);

    process.on('SIGINT', async () => {
      await server.close();
      process.exit(0);
    });
  }
}

main().catch((error: unknown) => {
  process.stderr.write(
    `Fatal error: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exit(1);
});
