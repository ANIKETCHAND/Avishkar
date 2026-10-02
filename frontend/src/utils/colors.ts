/**
 * Utility: Severity and Confidence color helpers
 */
import type { Severity, Confidence, PrivilegeLevel } from '../types';

export function severityColor(severity: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    LOW: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  };
  return map[severity] ?? 'text-slate-400 bg-slate-500/10 border-slate-500/30';
}

export function severityDot(severity: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-amber-500',
    LOW: 'bg-emerald-500',
  };
  return map[severity] ?? 'bg-slate-500';
}

export function confidenceColor(confidence: Confidence): string {
  const map: Record<Confidence, string> = {
    HIGH: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    LOW: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  };
  return map[confidence] ?? 'text-slate-400 bg-slate-500/10 border-slate-500/30';
}

export function privilegeColor(privilege: PrivilegeLevel): string {
  const map: Record<PrivilegeLevel, string> = {
    PUBLIC: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    USER: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    SERVICE: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
    ADMIN: 'text-red-400 bg-red-500/10 border-red-500/30',
    ELEVATED: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
    UNKNOWN: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  };
  return map[privilege] ?? 'text-slate-400 bg-slate-500/10 border-slate-500/30';
}

export function methodColor(method: string): string {
  const map: Record<string, string> = {
    GET: 'text-emerald-400 bg-emerald-500/10',
    POST: 'text-blue-400 bg-blue-500/10',
    PUT: 'text-amber-400 bg-amber-500/10',
    PATCH: 'text-amber-400 bg-amber-500/10',
    DELETE: 'text-red-400 bg-red-500/10',
  };
  return map[method.toUpperCase()] ?? 'text-slate-400 bg-slate-500/10';
}

export function ruleDescription(ruleId: string): string {
  const map: Record<string, string> = {
    'CD-001': 'Potential Privilege-Boundary Confused Deputy',
    'CD-002': 'Missing Downstream Authorization',
    'CD-003': 'Untrusted Identity Propagation',
    'CD-004': 'Gateway-Only Authorization Policy',
  };
  return map[ruleId] ?? ruleId;
}
