// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { CveResponse, CpeResponse, CvesResponse } from '../types/shodan.js';

function getCvssSeverity(score: number): string {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'None';
}

function formatCve(cve: CveResponse): object {
  return {
    'Basic Information': {
      'CVE ID': cve.cve_id,
      Published: new Date(cve.published_time).toLocaleString(),
      Summary: cve.summary,
    },
    'Severity Scores': {
      'CVSS v3': cve.cvss_v3
        ? { Score: cve.cvss_v3, Severity: getCvssSeverity(cve.cvss_v3) }
        : 'Not available',
      'CVSS v2': cve.cvss_v2
        ? { Score: cve.cvss_v2, Severity: getCvssSeverity(cve.cvss_v2) }
        : 'Not available',
      EPSS: cve.epss
        ? {
            Score: `${(cve.epss * 100).toFixed(2)}%`,
            Ranking: `Top ${(cve.ranking_epss * 100).toFixed(2)}%`,
          }
        : 'Not available',
    },
    'Impact Assessment': {
      'Known Exploited Vulnerability': cve.kev ? 'Yes' : 'No',
      'Proposed Action': cve.propose_action ?? 'No specific action proposed',
      'Ransomware Campaign': cve.ransomware_campaign ?? 'No known ransomware campaigns',
    },
    References:
      cve.references?.length > 0 ? cve.references : ['No references provided'],
  };
}

export async function handleCveLookup(
  cvedbClient: AxiosInstance,
  cveId: string
): Promise<object> {
  const response = await cvedbClient.get<CveResponse>(`/cve/${cveId.toUpperCase()}`);
  const result = response.data;

  return {
    ...formatCve(result),
    'Affected Products':
      result.cpes?.length > 0 ? result.cpes : ['No specific products listed'],
  };
}

export async function handleCpeLookup(
  cvedbClient: AxiosInstance,
  product: string,
  count: boolean,
  skip: number,
  limit: number
): Promise<object> {
  const response = await cvedbClient.get<CpeResponse>('/cpes', {
    params: { product, count, skip, limit },
  });

  if (count) {
    return { total_cpes: response.data.total };
  }

  return {
    cpes: response.data.cpes,
    skip,
    limit,
    total_returned: response.data.cpes.length,
  };
}

export async function handleCvesByProduct(
  cvedbClient: AxiosInstance,
  params: {
    cpe23?: string;
    product?: string;
    count?: boolean;
    is_kev?: boolean;
    sort_by_epss?: boolean;
    skip?: number;
    limit?: number;
    start_date?: string;
    end_date?: string;
  }
): Promise<object> {
  const response = await cvedbClient.get<CvesResponse>('/cves', { params });
  const result = response.data;

  const queryInfo = {
    Product: params.product ?? 'N/A',
    'CPE 2.3': params.cpe23 ?? 'N/A',
    'KEV Only': params.is_kev ? 'Yes' : 'No',
    'Sort by EPSS': params.sort_by_epss ? 'Yes' : 'No',
  };

  if (params.count) {
    return {
      'Query Information': queryInfo,
      Results: { 'Total CVEs Found': result.total },
    };
  }

  return {
    'Query Information': {
      ...queryInfo,
      'Date Range': params.start_date
        ? `${params.start_date} to ${params.end_date ?? 'now'}`
        : 'All dates',
    },
    'Results Summary': {
      'Total CVEs Found': result.total,
      'CVEs Returned': result.cves.length,
      Page: `${Math.floor((params.skip ?? 0) / (params.limit ?? 1000)) + 1}`,
      'CVEs per Page': params.limit ?? 1000,
    },
    Vulnerabilities: result.cves.map(formatCve),
  };
}
