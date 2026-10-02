/**
 * Main App Component
 * Orchestrates navigation between Upload, Dashboard, and Report views.
 */
import React, { useState } from 'react';
import { Shield, ArrowLeft, Share2, Table2, BarChart3, AlertTriangle } from 'lucide-react';
import type { ScanResult } from './types';
import { UploadPanel } from './components/UploadPanel';
import { ScanSummary } from './components/ScanSummary';
import { ArchitectureGraph } from './components/ArchitectureGraph';
import { FindingTable } from './components/FindingTable';
import { ReportPanel } from './components/ReportPanel';

type Tab = 'overview' | 'graph' | 'findings';

export default function App() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  const handleScanComplete = (result: ScanResult) => {
    setScanResult(result);
    setActiveTab('overview');
  };

  const reset = () => {
    setScanResult(null);
    setActiveTab('overview');
  };

  if (!scanResult) {
    return <UploadPanel onScanComplete={handleScanComplete} />;
  }

  const tabs: Array<{ id: Tab; label: string; icon: React.ReactNode; count?: number }> = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart3 className="w-4 h-4" />,
    },
    {
      id: 'graph',
      label: 'Architecture',
      icon: <Share2 className="w-4 h-4" />,
      count: scanResult.services.length,
    },
    {
      id: 'findings',
      label: 'Findings',
      icon: <AlertTriangle className="w-4 h-4" />,
      count: scanResult.findings.length,
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Top Nav */}
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-3 flex items-center gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2 shrink-0">
            <Shield className="w-5 h-5 text-blue-400" />
            <span className="text-slate-300 font-semibold text-sm hidden sm:block">Confused Deputy Detector</span>
          </div>

          <div className="w-px h-5 bg-slate-700" />

          {/* Tabs */}
          <nav className="flex items-center gap-1">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
                  ${activeTab === tab.id
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
              >
                {tab.icon}
                <span className="hidden sm:block">{tab.label}</span>
                {tab.count !== undefined && (
                  <span className={`px-1.5 py-0.5 rounded-full text-xs font-bold
                    ${activeTab === tab.id ? 'bg-blue-500/30 text-blue-200' : 'bg-slate-700 text-slate-400'}
                    ${tab.id === 'findings' && tab.count > 0 && activeTab !== tab.id
                      ? '!bg-red-500/20 !text-red-400'
                      : ''
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <ReportPanel scanResult={scanResult} />
            <button
              onClick={reset}
              className="flex items-center gap-1.5 text-slate-500 hover:text-slate-300 text-sm transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="hidden sm:block">New Scan</span>
            </button>
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-6 py-6">
        {/* Project Title */}
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold text-slate-100">{scanResult.project.project_name}</h1>
            {scanResult.findings.length === 0 ? (
              <span className="text-xs px-2 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full">
                ✓ Clean
              </span>
            ) : (
              <span className="text-xs px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/30 rounded-full">
                {scanResult.findings.length} finding{scanResult.findings.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>
          <div className="text-slate-500 text-sm">
            Confused Deputy Analysis · Python/FastAPI · Static Analysis
          </div>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && <ScanSummary scanResult={scanResult} />}

        {activeTab === 'graph' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-slate-200 font-semibold">Microservice Architecture</h2>
                <p className="text-slate-500 text-sm mt-0.5">
                  Click a service node to inspect its endpoints and related findings.
                  Red edges indicate potentially risky inter-service calls.
                </p>
              </div>
            </div>
            <ArchitectureGraph scanResult={scanResult} />
          </div>
        )}

        {activeTab === 'findings' && (
          <div>
            <div className="mb-4">
              <h2 className="text-slate-200 font-semibold">Security Findings</h2>
              <p className="text-slate-500 text-sm mt-0.5">
                Evidence-backed findings from static analysis. Each finding requires manual security review to confirm exploitability.
              </p>
            </div>
            <FindingTable findings={scanResult.findings} />
          </div>
        )}
      </main>
    </div>
  );
}
