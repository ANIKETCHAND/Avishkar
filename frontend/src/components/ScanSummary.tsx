/**
 * Summary Cards Component
 * Displays key metrics from the scan result.
 */
import React from 'react';
import { Shield, Server, Globe, AlertTriangle, Clock, FileText } from 'lucide-react';
import type { ScanResult } from '../types';

interface ScanSummaryProps {
  scanResult: ScanResult;
}

function StatCard({ icon, value, label, color }: {
  icon: React.ReactNode;
  value: string | number;
  label: string;
  color: string;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className={`inline-flex p-2 rounded-lg mb-3 ${color}`}>
        {icon}
      </div>
      <div className="text-3xl font-bold text-slate-100 mb-1">{value}</div>
      <div className="text-slate-500 text-sm">{label}</div>
    </div>
  );
}

export function ScanSummary({ scanResult }: ScanSummaryProps) {
  const stats = scanResult.summary_stats;
  const project = scanResult.project;

  const critical = stats.critical ?? 0;
  const high = stats.high ?? 0;
  const medium = stats.medium ?? 0;
  const low = stats.low ?? 0;
  const totalFindings = stats.total_findings ?? 0;

  return (
    <div>
      {/* Scan Info Banner */}
      <div className="flex flex-wrap items-center gap-4 p-4 bg-slate-900 border border-slate-800 rounded-xl mb-6">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-slate-300 font-medium">{project.project_name}</span>
        </div>
        <div className="flex items-center gap-1 text-slate-500 text-sm">
          <Clock className="w-4 h-4" />
          <span>
            {scanResult.scan_duration_seconds != null
              ? `${scanResult.scan_duration_seconds.toFixed(2)}s`
              : 'N/A'}
          </span>
        </div>
        <div className="flex items-center gap-1 text-slate-500 text-sm">
          <FileText className="w-4 h-4" />
          <span>{project.total_files} files analyzed</span>
        </div>
        <div className="ml-auto text-slate-500 text-sm font-mono">{scanResult.scan_id}</div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          icon={<Server className="w-5 h-5 text-blue-400" />}
          value={stats.total_services ?? scanResult.services.length}
          label="Services Discovered"
          color="bg-blue-500/10"
        />
        <StatCard
          icon={<Globe className="w-5 h-5 text-purple-400" />}
          value={stats.total_endpoints ?? scanResult.endpoints.length}
          label="API Endpoints"
          color="bg-purple-500/10"
        />
        <StatCard
          icon={<Shield className="w-5 h-5 text-slate-400" />}
          value={stats.total_service_calls ?? scanResult.service_calls.length}
          label="Service Calls"
          color="bg-slate-500/10"
        />
        <StatCard
          icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
          value={totalFindings}
          label="Total Findings"
          color="bg-red-500/10"
        />
      </div>

      {/* Severity Breakdown */}
      {totalFindings > 0 && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl mb-6">
          <div className="text-slate-400 text-sm font-medium mb-3">Severity Breakdown</div>
          <div className="flex gap-3 flex-wrap">
            {critical > 0 && (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 border border-red-500/30 rounded-lg">
                <div className="w-2 h-2 rounded-full bg-red-500" />
                <span className="text-red-400 font-semibold text-sm">{critical} Critical</span>
              </div>
            )}
            {high > 0 && (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-orange-500/10 border border-orange-500/30 rounded-lg">
                <div className="w-2 h-2 rounded-full bg-orange-500" />
                <span className="text-orange-400 font-semibold text-sm">{high} High</span>
              </div>
            )}
            {medium > 0 && (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <div className="w-2 h-2 rounded-full bg-amber-500" />
                <span className="text-amber-400 font-semibold text-sm">{medium} Medium</span>
              </div>
            )}
            {low > 0 && (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                <div className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className="text-emerald-400 font-semibold text-sm">{low} Low</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* No Findings Banner */}
      {totalFindings === 0 && (
        <div className="flex items-center gap-4 p-5 bg-emerald-500/5 border border-emerald-500/20 rounded-xl mb-6">
          <div className="p-3 bg-emerald-500/10 rounded-xl">
            <Shield className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="text-emerald-400 font-semibold">No Confused Deputy Findings Detected</div>
            <div className="text-slate-500 text-sm mt-0.5">
              Static analysis did not identify potential confused deputy authorization risks.
              Manual security review is still recommended.
            </div>
          </div>
        </div>
      )}

      {/* Warnings */}
      {scanResult.warnings.length > 0 && (
        <div className="p-4 bg-amber-500/5 border border-amber-500/20 rounded-xl mb-6">
          <div className="text-amber-400 text-sm font-medium mb-2">Analysis Warnings</div>
          <ul className="space-y-1">
            {scanResult.warnings.map((w, i) => (
              <li key={i} className="text-slate-400 text-sm flex items-start gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mt-0.5 shrink-0" />
                {w}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
