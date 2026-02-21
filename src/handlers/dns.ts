// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { DnsResponse, ReverseDnsResponse } from '../types/shodan.js';

export async function handleDnsLookup(
  client: AxiosInstance,
  hostnames: string[]
): Promise<object> {
  const response = await client.get<DnsResponse>('/dns/resolve', {
    params: { hostnames: hostnames.join(',') },
  });

  return {
    'DNS Resolutions': Object.entries(response.data).map(([hostname, ip]) => ({
      Hostname: hostname,
      'IP Address': ip,
    })),
    Summary: {
      'Total Lookups': Object.keys(response.data).length,
      'Queried Hostnames': hostnames,
    },
  };
}

export async function handleReverseDnsLookup(
  client: AxiosInstance,
  ips: string[]
): Promise<object> {
  const response = await client.get<ReverseDnsResponse>('/dns/reverse', {
    params: { ips: ips.join(',') },
  });

  return {
    'Reverse DNS Resolutions': Object.entries(response.data).map(([ip, hostnames]) => ({
      'IP Address': ip,
      Hostnames: hostnames.length > 0 ? hostnames : ['No hostnames found'],
    })),
    Summary: {
      'Total IPs Queried': ips.length,
      'IPs with Results': Object.keys(response.data).length,
      'Queried IP Addresses': ips,
    },
  };
}
