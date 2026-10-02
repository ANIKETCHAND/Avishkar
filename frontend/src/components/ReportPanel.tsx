/**
 * Report Panel Component
 * Download options for JSON and HTML reports.
 */
import React from 'react';
import { Download, FileJson, FileText } from 'lucide-react';
import type { ScanResult } from '../types';
import { downloadJson, downloadHtmlReport } from '../utils/api';

interface ReportPanelProps {
  scanResult: ScanResult;
}

export function ReportPanel({ scanResult }: ReportPanelProps) {
  const [downloading, setDownloading] = React.useState<string | null>(null);

  const handleDownloadHtml = async () => {
    setDownloading('html');
    try {
      await downloadHtmlReport(scanResult.scan_id, scanResult.project.project_name);
    } finally {
      setDownloading(null);
    }
  };

  const handleDownloadJson = () => {
    downloadJson(scanResult);
  };

  return (
    <div className="flex flex-wrap gap-3">
      <button
        onClick={handleDownloadHtml}
        disabled={downloading === 'html'}
        className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-500
          text-white rounded-lg font-medium text-sm transition-colors disabled:opacity-50"
      >
        <FileText className="w-4 h-4" />
        {downloading === 'html' ? 'Generating...' : 'Download HTML Report'}
      </button>
      <button
        onClick={handleDownloadJson}
        className="flex items-center gap-2 px-4 py-2.5 bg-slate-700 hover:bg-slate-600
          text-slate-200 rounded-lg font-medium text-sm transition-colors"
      >
        <FileJson className="w-4 h-4" />
        Download JSON
      </button>
      <div className="text-slate-600 text-xs self-center ml-2">
        Scan ID: <span className="font-mono text-slate-500">{scanResult.scan_id}</span>
      </div>
    </div>
  );
}
