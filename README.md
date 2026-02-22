# Shodan MCP Server

[![npm version](https://img.shields.io/npm/v/@tocharianou/mcp-shodan)](https://www.npmjs.com/package/@tocharianou/mcp-shodan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that provides network intelligence and vulnerability research tools powered by the [Shodan API](https://shodan.io) and [Shodan CVEDB](https://cvedb.shodan.io). Query IP addresses, search internet-connected devices, resolve DNS, and look up CVEs directly from your AI assistant.

## Quick Start

### Claude Desktop (stdio)

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shodan": {
      "command": "npx",
      "args": ["-y", "@tocharianou/mcp-shodan"],
      "env": {
        "SHODAN_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

Get your API key at [account.shodan.io](https://account.shodan.io).

### HTTP / Streamable mode

```bash
MCP_TRANSPORT=http MCP_HTTP_PORT=3001 SHODAN_API_KEY=<key> npx @tocharianou/mcp-shodan
```

Then point your MCP client at `http://localhost:3001/mcp`.

## Features

- **IP reconnaissance** — open ports, running services, banners, SSL certificates, cloud provider detection
- **Device search** — query Shodan's internet-wide scan database with advanced filters and geographic distribution
- **DNS operations** — forward and reverse DNS lookups for domains and IP addresses
- **Vulnerability intelligence** — CVE details (CVSS v2/v3, EPSS, KEV status), CPE lookups, and product-specific CVE tracking via CVEDB

## Configuration

| Environment variable | Required | Description |
|---|---|---|
| `SHODAN_API_KEY` | ✓\* | Shodan API key, appended as `?key=` query parameter (direct mode) |
| `SHODAN_BASE_URL` | – | Override API base URL (e.g. proxy endpoint). Default: `https://api.shodan.io` |
| `SHODAN_AUTH_TOKEN` | ✓\* | Bearer token for proxy authentication |
| `SHODAN_CVEDB_URL` | – | Override CVEDB base URL. Default: `https://cvedb.shodan.io` |
| `SHODAN_TIMEOUT` | – | Request timeout in ms (default: `30000`) |
| `MCP_TRANSPORT` | – | `stdio` (default) or `http` |
| `MCP_HTTP_PORT` | – | HTTP server port (default: `3001`) |
| `MCP_HTTP_HOST` | – | HTTP server host (default: `localhost`) |

\* Either `SHODAN_API_KEY` (direct) **or** `SHODAN_BASE_URL` + `SHODAN_AUTH_TOKEN` (proxy) must be set.

> **Note**: The CVEDB endpoints (`cve_lookup`, `cpe_lookup`, `cves_by_product`) are publicly accessible and do not require an API key.

### Direct vs Proxy mode

**Direct mode** — the server calls Shodan directly using your own API key:
```
SHODAN_API_KEY=YOUR_KEY_HERE
```

**Proxy mode** — the server calls a backend gateway that injects the real API key and handles billing. The server authenticates to the gateway using a Bearer token:
```
SHODAN_BASE_URL=https://gateway.example.com/shodan
SHODAN_AUTH_TOKEN=YOUR_BEARER_TOKEN
```

The tool itself is mode-agnostic; the calling application sets the appropriate variables.

## Available Tools

| Tool | Description | Requires paid key |
|------|-------------|:-----------------:|
| `ip_lookup` | IP address analysis: ports, services, banners, cloud provider, hostnames | ✓ |
| `shodan_search` | Search internet-connected devices with country distribution stats | ✓ |
| `dns_lookup` | Batch forward DNS resolution (hostnames → IPs) | ✓ |
| `reverse_dns_lookup` | Batch reverse DNS lookup (IPs → hostnames) | ✓ |
| `cve_lookup` | CVE details: CVSS v2/v3, EPSS, KEV status, ransomware associations | – |
| `cpe_lookup` | Search CPE entries by product name with pagination | – |
| `cves_by_product` | All CVEs for a product or CPE 2.3 identifier with filtering | – |

## Example Queries

- *"What ports and services are exposed on IP 8.8.8.8?"*
- *"Search Shodan for Apache servers in Germany: `apache country:DE`"*
- *"Resolve these hostnames to IP addresses: github.com, google.com"*
- *"What is the severity and KEV status of CVE-2021-44228?"*
- *"List all CVEs affecting log4j sorted by EPSS score"*

## Debugging

Use the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) to test and debug:

```bash
npm run inspector
```

Server logs are written to **stderr** so they do not interfere with the MCP JSON-RPC stream on stdout.

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `Request failed with status code 401` | Invalid or missing `SHODAN_API_KEY` |
| `Request failed with status code 402` | Out of Shodan query credits |
| `Request failed with status code 403` | API plan does not support this endpoint (requires paid membership) |
| `Request failed with status code 429` | Rate limit exceeded |
| Tool calls time out | Increase `SHODAN_TIMEOUT` or check network connectivity |

## Development

```bash
git clone https://github.com/TocharianOU/mcp-shodan.git
cd mcp-shodan
npm install --ignore-scripts
npm run build
cp .env.example .env   # fill in your API key
npm start
```

## Release

See [RELEASE.md](RELEASE.md) for the full release process.

## License

[MIT](LICENSE) — Copyright © 2024 TocharianOU

> **Disclaimer**: This project is a fork of [BurtTheCoder/mcp-shodan](https://github.com/BurtTheCoder/mcp-shodan), extended with dual-transport support, Hub proxy mode, and TocharianOU project conventions. It is community-maintained and not affiliated with or endorsed by Shodan.
