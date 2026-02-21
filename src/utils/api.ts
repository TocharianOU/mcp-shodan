// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import axios, { AxiosInstance } from 'axios';
import { ShodanConfig } from '../types.js';

const DEFAULT_SHODAN_URL = 'https://api.shodan.io';
const DEFAULT_CVEDB_URL = 'https://cvedb.shodan.io';

/**
 * Create an axios instance for the Shodan main API.
 *
 * Auth priority:
 *   1. apiKey  → appended as ?key= query param (BYOK direct mode)
 *   2. authToken → Authorization: Bearer  (Hub proxy mode)
 *
 * In proxy (Hub) mode the backend strips the Bearer token and injects
 * the real Shodan API key before forwarding to api.shodan.io.
 */
export function createShodanClient(config: ShodanConfig): AxiosInstance {
  const baseURL = config.baseUrl ?? DEFAULT_SHODAN_URL;
  const headers: Record<string, string> = {};

  if (config.authToken && !config.apiKey) {
    headers['Authorization'] = `Bearer ${config.authToken}`;
  }

  const client = axios.create({ baseURL, headers, timeout: config.timeout });

  if (config.apiKey) {
    client.interceptors.request.use((reqConfig) => {
      reqConfig.params = { ...reqConfig.params, key: config.apiKey };
      return reqConfig;
    });
  }

  return client;
}

/**
 * Create an axios instance for the Shodan CVEDB API.
 *
 * CVEDB is a public endpoint that does not require authentication.
 */
export function createCvedbClient(config: ShodanConfig): AxiosInstance {
  const baseURL = config.cvedbUrl ?? DEFAULT_CVEDB_URL;
  return axios.create({ baseURL, timeout: config.timeout });
}
