/**
 * Finding Details Component
 * Full evidence-backed finding display with observations, remediation, and code snippet.
 */
import React, { useState } from 'react';
import { AlertTriangle, Shield, Code, ChevronDown, ChevronUp, Copy, CheckCircle } from 'lucide-react';
import type { Finding } from '../types';
import { severityColor, confidenceColor, severityDot } from '../utils/colors';

interface FindingTableProps {
  findings: Finding[];
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={copy} className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded">
      {copied ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

function FindingCard({ finding, isExpanded, onToggle }: {
  finding: Finding;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className={`
      border rounded-xl overflow-hidden transition-all
      ${finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
        ? 'border-red-500/30'
        : finding.severity === 'MEDIUM'
        ? 'border-amber-500/30'
        : 'border-emerald-500/30'
      }
    `}>
      {/* Header - always visible */}
      <div
        className="flex items-start gap-4 p-4 cursor-pointer hover:bg-slate-900/50 transition-colors"
        onClick={onToggle}
      >
        <div className={`w-1.5 h-full rounded-full shrink-0 mt-0.5 ${severityDot(finding.severity)}`} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold ${severityColor(finding.severity)}`}>
              {finding.severity}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${confidenceColor(finding.confidence)}`}>
              CONF: {finding.confidence}
            </span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/30">
              {finding.rule_id}
            </span>
          </div>
          <div className="text-slate-100 font-semibold">{finding.title}</div>
          <div className="text-slate-500 text-xs mt-1 font-mono">
            {finding.source_service_id} → {finding.destination_service_id}
            {finding.source_file && ` · ${finding.source_file}:${finding.line_number}`}
          </div>
        </div>

        <div className="shrink-0 text-slate-500">
          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="border-t border-slate-800 p-4 space-y-4 bg-slate-900/30">

          {/* Authorization Observations */}
          <div>
            <div className="text-slate-400 text-xs font-semibold uppercase mb-2 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5" /> Authorization Observations
            </div>
            <ul className="space-y-1.5">
              {finding.authorization_observations.map((obs, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="text-blue-400 shrink-0">▸</span>
                  {obs}
                </li>
              ))}
            </ul>
          </div>

          {/* Privilege Observations */}
          <div>
            <div className="text-slate-400 text-xs font-semibold uppercase mb-2 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> Privilege Observations
            </div>
            <ul className="space-y-1.5">
              {finding.privilege_observations.map((obs, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="text-purple-400 shrink-0">▸</span>
                  {obs}
                </li>
              ))}
            </ul>
          </div>

          {/* Code Evidence */}
          <div>
            <div className="text-slate-400 text-xs font-semibold uppercase mb-2 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5" /> Code Evidence
              </span>
              <CopyButton text={finding.evidence_snippet} />
            </div>
            <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap">
              {finding.evidence_snippet}
            </pre>
          </div>

          {/* Limitations */}
          <div className="p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg text-xs text-amber-400/80">
            <span className="font-semibold">⚠ Static Analysis Limitations: </span>
            {finding.limitations}
          </div>

          {/* Remediation */}
          <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
            <div className="text-blue-400 text-xs font-semibold mb-2">🔧 Recommended Remediation</div>
            <pre className="text-slate-400 text-xs whitespace-pre-wrap font-mono">{finding.remediation}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

export function FindingTable({ findings }: FindingTableProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterRule, setFilterRule] = useState<string>('ALL');

  const toggle = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const filtered = findings.filter(f => {
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    if (filterRule !== 'ALL' && f.rule_id !== filterRule) return false;
    return true;
  });

  const severities = Array.from(new Set(findings.map(f => f.severity)));
  const rules = Array.from(new Set(findings.map(f => f.rule_id)));

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-slate-500">
        <Shield className="w-12 h-12 mb-3 opacity-30 text-emerald-500" />
        <p className="text-emerald-400 font-medium">No findings detected</p>
        <p className="text-sm mt-1">Static analysis found no potential confused deputy risks.</p>
      </div>
    );
  }

  return (
    <div>
      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-slate-500 text-sm">Severity:</span>
          <div className="flex gap-1">
            {['ALL', ...severities].map(s => (
              <button
                key={s}
                onClick={() => setFilterSeverity(s)}
                className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors
                  ${filterSeverity === s
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-500 text-sm">Rule:</span>
          <div className="flex gap-1">
            {['ALL', ...rules].map(r => (
              <button
                key={r}
                onClick={() => setFilterRule(r)}
                className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors
                  ${filterRule === r
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
        <div className="ml-auto text-slate-500 text-sm self-center">
          {filtered.length} of {findings.length} findings
        </div>
      </div>

      {/* Finding Cards */}
      <div className="space-y-3">
        {filtered.map(finding => (
          <FindingCard
            key={finding.finding_id}
            finding={finding}
            isExpanded={expandedIds.has(finding.finding_id)}
            onToggle={() => toggle(finding.finding_id)}
          />
        ))}
      </div>
    </div>
  );
}
