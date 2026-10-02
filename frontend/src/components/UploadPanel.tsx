/**
 * Upload Panel Component
 * Drag-and-drop ZIP upload with benchmark buttons.
 */
import React, { useCallback, useState, useRef } from 'react';
import { Upload, Shield, AlertTriangle, CheckCircle, Loader2, ChevronRight } from 'lucide-react';
import { uploadScan, runDemoScan, ApiError } from '../utils/api';
import type { ScanResult } from '../types';

interface UploadPanelProps {
  onScanComplete: (result: ScanResult) => void;
}

export function UploadPanel({ onScanComplete }: UploadPanelProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanLabel, setScanLabel] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleError = (e: unknown) => {
    if (e instanceof ApiError) {
      setError(e.message);
    } else if (e instanceof Error) {
      setError(e.message);
    } else {
      setError('An unexpected error occurred');
    }
  };

  const handleFile = useCallback((file: File) => {
    if (!file.name.endsWith('.zip')) {
      setError('Only .zip archives are supported. Please package your microservices as a ZIP file.');
      return;
    }
    setSelectedFile(file);
    setError(null);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  };

  const startScan = async () => {
    if (!selectedFile) return;
    setIsScanning(true);
    setScanLabel(`Analyzing ${selectedFile.name}...`);
    setError(null);
    try {
      const result = await uploadScan(selectedFile);
      onScanComplete(result);
    } catch (e) {
      handleError(e);
    } finally {
      setIsScanning(false);
    }
  };

  const runDemo = async (type: 'vulnerable' | 'secure') => {
    setIsScanning(true);
    setScanLabel(`Running ${type} benchmark...`);
    setError(null);
    setSelectedFile(null);
    try {
      const result = await runDemoScan(type);
      onScanComplete(result);
    } catch (e) {
      handleError(e);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-6">
      {/* Hero */}
      <div className="mb-10 text-center">
        <div className="flex items-center justify-center gap-3 mb-4">
          <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
          <h1 className="text-3xl font-bold text-slate-100">Confused Deputy Detector</h1>
        </div>
        <p className="text-slate-400 max-w-xl">
          Specialized static analyzer for detecting potential confused-deputy authorization risks
          across Python/FastAPI microservice boundaries.
        </p>
        <div className="flex items-center justify-center gap-6 mt-4 text-sm text-slate-500">
          <span className="flex items-center gap-1"><CheckCircle className="w-4 h-4 text-emerald-500" /> Never executes uploaded code</span>
          <span className="flex items-center gap-1"><CheckCircle className="w-4 h-4 text-emerald-500" /> 100% static analysis</span>
          <span className="flex items-center gap-1"><CheckCircle className="w-4 h-4 text-emerald-500" /> Evidence-backed findings</span>
        </div>
      </div>

      {/* Upload Card */}
      <div className="w-full max-w-2xl">
        {/* Drop Zone */}
        <div
          className={`border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer mb-4
            ${isDragging
              ? 'border-blue-400 bg-blue-500/10'
              : selectedFile
              ? 'border-emerald-500/50 bg-emerald-500/5'
              : 'border-slate-600 hover:border-slate-500 bg-slate-900/50 hover:bg-slate-900'
            }`}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => !selectedFile && fileInputRef.current?.click()}
        >
          {selectedFile ? (
            <div>
              <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <p className="text-emerald-400 font-semibold">{selectedFile.name}</p>
              <p className="text-slate-500 text-sm mt-1">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB · Click to change
              </p>
              <button
                className="mt-2 text-xs text-slate-500 hover:text-slate-400 underline"
                onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
              >
                Clear
              </button>
            </div>
          ) : (
            <div>
              <Upload className={`w-10 h-10 mx-auto mb-3 ${isDragging ? 'text-blue-400' : 'text-slate-500'}`} />
              <p className="text-slate-300 font-medium">Drop your microservices ZIP here</p>
              <p className="text-slate-500 text-sm mt-1">or click to browse · Max 50 MB · .zip only</p>
            </div>
          )}
          <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={handleFileInput} />
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 p-4 bg-red-500/10 border border-red-500/30 rounded-lg mb-4 text-red-400 text-sm">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Scan Button */}
        <button
          onClick={startScan}
          disabled={!selectedFile || isScanning}
          className={`w-full py-3 px-6 rounded-lg font-semibold flex items-center justify-center gap-2 transition-all
            ${selectedFile && !isScanning
              ? 'bg-blue-600 hover:bg-blue-500 text-white cursor-pointer'
              : 'bg-slate-800 text-slate-500 cursor-not-allowed'
            }`}
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              {scanLabel}
            </>
          ) : (
            <>
              <Shield className="w-4 h-4" />
              Run Confused Deputy Analysis
            </>
          )}
        </button>

        {/* Divider */}
        <div className="flex items-center gap-4 my-6">
          <div className="flex-1 border-t border-slate-800" />
          <span className="text-slate-600 text-sm">or try a benchmark</span>
          <div className="flex-1 border-t border-slate-800" />
        </div>

        {/* Demo Buttons */}
        <div className="grid grid-cols-2 gap-3">
          <button
            onClick={() => runDemo('vulnerable')}
            disabled={isScanning}
            className="p-4 rounded-lg border border-red-500/30 bg-red-500/5 hover:bg-red-500/10
              text-left transition-all disabled:opacity-50 disabled:cursor-not-allowed group"
          >
            <div className="flex items-center justify-between mb-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <ChevronRight className="w-4 h-4 text-red-400/50 group-hover:translate-x-0.5 transition-transform" />
            </div>
            <div className="text-red-400 font-semibold text-sm">Vulnerable Benchmark</div>
            <div className="text-slate-500 text-xs mt-0.5">
              Order→Payment without user ownership check
            </div>
          </button>

          <button
            onClick={() => runDemo('secure')}
            disabled={isScanning}
            className="p-4 rounded-lg border border-emerald-500/30 bg-emerald-500/5 hover:bg-emerald-500/10
              text-left transition-all disabled:opacity-50 disabled:cursor-not-allowed group"
          >
            <div className="flex items-center justify-between mb-2">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
              <ChevronRight className="w-4 h-4 text-emerald-400/50 group-hover:translate-x-0.5 transition-transform" />
            </div>
            <div className="text-emerald-400 font-semibold text-sm">Secure Benchmark</div>
            <div className="text-slate-500 text-xs mt-0.5">
              With user JWT forwarding and ownership validation
            </div>
          </button>
        </div>

        {/* Disclaimer */}
        <p className="text-center text-slate-600 text-xs mt-6">
          Uploaded code is never executed. All analysis is static only.
          Findings represent potential risks requiring manual security review.
        </p>
      </div>
    </div>
  );
}
