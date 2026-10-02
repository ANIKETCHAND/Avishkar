/**
 * API client for the Confused Deputy Detector backend.
 * All communication goes through the FastAPI REST layer.
 */

import type { ScanResult, ScanSummary } from '../types';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch { /* ignore */ }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

/**
 * Upload a ZIP archive and start a scan.
 */
export async function uploadScan(file: File, projectName?: string): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', file);
  if (projectName) {
    formData.append('project_name', projectName);
  }

  const res = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    body: formData,
  });

  return handleResponse<ScanResult>(res);
}

/**
 * Run the demo benchmark scan (vulnerable or secure).
 */
export async function runDemoScan(demoType: 'vulnerable' | 'secure'): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('demo_type', demoType);

  const res = await fetch(`${API_BASE}/scan/demo`, {
    method: 'POST',
    body: formData,
  });

  return handleResponse<ScanResult>(res);
}

/**
 * Retrieve a scan result by ID.
 */
export async function getScan(scanId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`);
  return handleResponse<ScanResult>(res);
}

/**
 * List recent scans.
 */
export async function listScans(limit?: number): Promise<ScanSummary[]> {
  const url = limit ? `${API_BASE}/scans?limit=${limit}` : `${API_BASE}/scans`;
  const res = await fetch(url);
  return handleResponse<ScanSummary[]>(res);
}

/**
 * Get the HTML report URL for a scan.
 */
export function getHtmlReportUrl(scanId: string): string {
  return `${API_BASE}/scans/${scanId}/export/html`;
}

/**
 * Download the HTML report for a scan.
 */
export async function downloadHtmlReport(scanId: string, projectName: string): Promise<void> {
  const res = await fetch(getHtmlReportUrl(scanId));
  if (!res.ok) throw new ApiError(res.status, 'Failed to generate HTML report');

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `confused_deputy_report_${projectName.replace(/[^a-z0-9]/gi, '_')}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Download scan result as JSON.
 */
export function downloadJson(scanResult: ScanResult): void {
  const json = JSON.stringify(scanResult, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan_${scanResult.scan_id}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
