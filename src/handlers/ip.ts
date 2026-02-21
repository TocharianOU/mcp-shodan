// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { ShodanHostResponse, ShodanService, SearchResponse } from '../types/shodan.js';

export async function handleIpLookup(
  client: AxiosInstance,
  ip: string
): Promise<object> {
  const response = await client.get<ShodanHostResponse>(`/shodan/host/${ip}`);
  const result = response.data;

  return {
    'IP Information': {
      'IP Address': result.ip_str,
      Organization: result.org,
      ISP: result.isp,
      ASN: result.asn,
      'Last Update': result.last_update,
    },
    Location: {
      Country: result.country_name,
      City: result.city,
      Coordinates: `${result.latitude}, ${result.longitude}`,
      Region: result.region_code,
    },
    Services: result.ports.map((port: number) => {
      const service = result.data.find((d: ShodanService) => d.port === port);
      return {
        Port: port,
        Protocol: service?.transport ?? 'unknown',
        Service: service?.data?.trim() ?? 'No banner',
        ...(service?.http
          ? {
              HTTP: {
                Server: service.http.server,
                Title: service.http.title,
              },
            }
          : {}),
      };
    }),
    'Cloud Provider':
      result.data[0]?.cloud
        ? {
            Provider: result.data[0].cloud.provider,
            Service: result.data[0].cloud.service,
            Region: result.data[0].cloud.region,
          }
        : 'Not detected',
    Hostnames: result.hostnames ?? [],
    Domains: result.domains ?? [],
    Tags: result.tags ?? [],
  };
}

export async function handleShodanSearch(
  client: AxiosInstance,
  query: string,
  maxResults: number
): Promise<object> {
  const response = await client.get<SearchResponse>('/shodan/host/search', {
    params: { query, limit: maxResults },
  });
  const result = response.data;

  return {
    'Search Summary': {
      Query: query,
      'Total Results': result.total,
      'Results Returned': result.matches.length,
    },
    'Country Distribution':
      result.facets?.country?.map((c) => ({
        Country: c.value,
        Count: c.count,
        Percentage: `${((c.count / result.total) * 100).toFixed(2)}%`,
      })) ?? [],
    Matches: result.matches.map((match) => ({
      'Basic Information': {
        'IP Address': match.ip_str,
        Organization: match.org,
        ISP: match.isp,
        ASN: match.asn,
        'Last Update': match.timestamp,
      },
      Location: {
        Country: match.location.country_name,
        City: match.location.city ?? 'Unknown',
        Region: match.location.region_code ?? 'Unknown',
        Coordinates: `${match.location.latitude}, ${match.location.longitude}`,
      },
      'Service Details': {
        Port: match.port,
        Transport: match.transport,
        Product: match.product ?? 'Unknown',
        Version: match.version ?? 'Unknown',
        CPE: match.cpe ?? [],
      },
      'Web Information': match.http
        ? {
            Server: match.http.server,
            Title: match.http.title,
            'Robots.txt': match.http.robots ? 'Present' : 'Not found',
            Sitemap: match.http.sitemap ? 'Present' : 'Not found',
          }
        : 'No HTTP information',
      Hostnames: match.hostnames,
      Domains: match.domains,
    })),
  };
}
