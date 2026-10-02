/**
 * Architecture Graph Component
 * Interactive React Flow canvas showing services, endpoints, and inter-service calls.
 * Uses custom ServiceNode and RiskEdge components.
 */
import React, { useMemo, useCallback, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  type NodeProps,
  type EdgeProps,
  getBezierPath,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { AlertTriangle, Shield, Server, ChevronRight } from 'lucide-react';
import type { ScanResult, GraphNode as ApiGraphNode, GraphEdge as ApiGraphEdge } from '../types';
import { privilegeColor, severityColor } from '../utils/colors';

// ── Custom Service Node ───────────────────────────────────────────────────

function ServiceNode({ data }: NodeProps) {
  const nodeData = data as {
    label: string;
    privilege?: string;
    confidence?: string;
    endpointsCount?: number;
    hasRisk?: boolean;
  };

  const privilegeBadge = nodeData.privilege ?? 'UNKNOWN';
  const privClass = privilegeColor(privilegeBadge as any);

  return (
    <div className={`
      bg-slate-900 border rounded-xl p-4 min-w-[180px] shadow-lg
      ${nodeData.hasRisk ? 'border-red-500/50 shadow-red-500/10' : 'border-slate-700'}
    `}>
      <Handle type="target" position={Position.Top} className="!bg-slate-600 !border-slate-500 !w-2 !h-2" />

      <div className="flex items-start gap-2 mb-3">
        <div className={`p-1.5 rounded-lg shrink-0 ${nodeData.hasRisk ? 'bg-red-500/10' : 'bg-blue-500/10'}`}>
          {nodeData.hasRisk
            ? <AlertTriangle className="w-4 h-4 text-red-400" />
            : <Server className="w-4 h-4 text-blue-400" />
          }
        </div>
        <div className="min-w-0">
          <div className="text-slate-100 font-semibold text-sm truncate">{nodeData.label}</div>
          {nodeData.hasRisk && (
            <div className="text-red-400 text-xs">⚠ Risk Detected</div>
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5 mb-2">
        <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${privClass}`}>
          {privilegeBadge}
        </span>
        {nodeData.confidence && (
          <span className="text-xs px-2 py-0.5 rounded-full border text-slate-400 border-slate-600">
            {nodeData.confidence}
          </span>
        )}
      </div>

      {nodeData.endpointsCount !== undefined && (
        <div className="text-slate-500 text-xs">
          {nodeData.endpointsCount} endpoint{nodeData.endpointsCount !== 1 ? 's' : ''}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-slate-600 !border-slate-500 !w-2 !h-2" />
    </div>
  );
}

// ── Custom Risk Edge ──────────────────────────────────────────────────────

function RiskEdge({
  id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, label
}: EdgeProps) {
  const edgeData = data as { risk?: boolean; severity?: string; riskRule?: string } | undefined;
  const isRisky = edgeData?.risk;

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX, sourceY, sourcePosition,
    targetX, targetY, targetPosition,
  });

  const strokeColor = isRisky
    ? (edgeData?.severity === 'CRITICAL' ? '#ef4444' : '#f97316')
    : '#475569';
  const strokeWidth = isRisky ? 2.5 : 1.5;

  return (
    <>
      {isRisky && (
        <path
          d={edgePath}
          stroke={strokeColor}
          strokeWidth={strokeWidth + 6}
          opacity={0.15}
          fill="none"
        />
      )}
      <path
        id={id}
        d={edgePath}
        stroke={strokeColor}
        strokeWidth={strokeWidth}
        fill="none"
        strokeDasharray={isRisky ? '6 3' : undefined}
        className={isRisky ? 'animate-pulse' : undefined}
      />
      {label && (
        <foreignObject
          x={labelX - 60}
          y={labelY - 12}
          width={120}
          height={24}
          className="overflow-visible"
        >
          <div className="flex justify-center">
            <span className={`
              text-xs px-2 py-0.5 rounded font-mono whitespace-nowrap
              ${isRisky
                ? 'bg-red-900/80 text-red-300 border border-red-500/30'
                : 'bg-slate-800/90 text-slate-400 border border-slate-700'
              }
            `}>
              {String(label)}
            </span>
          </div>
        </foreignObject>
      )}
    </>
  );
}

// ── Layout Helper ─────────────────────────────────────────────────────────

function layoutNodes(apiNodes: ApiGraphNode[]): Map<string, { x: number; y: number }> {
  const serviceNodes = apiNodes.filter(n => n.type === 'SERVICE_NODE');
  const positions = new Map<string, { x: number; y: number }>();

  const cols = Math.ceil(Math.sqrt(serviceNodes.length));
  serviceNodes.forEach((node, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    positions.set(node.id, {
      x: col * 280 + 60,
      y: row * 220 + 60,
    });
  });

  return positions;
}

// ── Architecture Graph ────────────────────────────────────────────────────

interface ArchitectureGraphProps {
  scanResult: ScanResult;
  onNodeClick?: (nodeId: string) => void;
  onEdgeClick?: (edgeId: string) => void;
}

const nodeTypes = { serviceNode: ServiceNode };
const edgeTypes = { riskEdge: RiskEdge };

export function ArchitectureGraph({ scanResult, onNodeClick }: ArchitectureGraphProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  // Convert API graph model to React Flow format
  const { initialNodes, initialEdges } = useMemo(() => {
    const { nodes: apiNodes, edges: apiEdges } = scanResult.graph;

    // Only show service nodes in the main graph (not endpoint nodes — too many)
    const serviceApiNodes = apiNodes.filter(n => n.type === 'SERVICE_NODE');
    const positions = layoutNodes(serviceApiNodes);

    const rfNodes: Node[] = serviceApiNodes.map(node => ({
      id: node.id,
      type: 'serviceNode',
      position: positions.get(node.id) ?? { x: 0, y: 0 },
      data: {
        label: node.label,
        ...node.data,
      },
    }));

    // Only show SERVICE_CALL edges between service nodes
    const serviceNodeIds = new Set(serviceApiNodes.map(n => n.id));
    const rfEdges: Edge[] = apiEdges
      .filter(e => serviceNodeIds.has(e.source) && serviceNodeIds.has(e.target))
      .map(edge => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: 'riskEdge',
        label: edge.label,
        data: edge.data,
        animated: edge.data?.risk === true,
        markerEnd: {
          type: 'arrowclosed' as const,
          color: edge.data?.risk ? '#ef4444' : '#475569',
        },
      }));

    return { initialNodes: rfNodes, initialEdges: rfEdges };
  }, [scanResult]);

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node.id === selectedNode ? null : node.id);
    onNodeClick?.(node.id);
  }, [selectedNode, onNodeClick]);

  // Find selected service info
  const selectedService = selectedNode
    ? scanResult.services.find(s => s.service_id === selectedNode)
    : null;
  const selectedEndpoints = selectedNode
    ? scanResult.endpoints.filter(e => e.service_id === selectedNode)
    : [];
  const selectedFindings = selectedNode
    ? scanResult.findings.filter(
        f => f.source_service_id === selectedNode || f.destination_service_id === selectedNode
      )
    : [];

  if (nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-96 text-slate-500">
        <div className="text-center">
          <Server className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No service nodes to display</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex gap-4 h-[600px]">
      <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} color="#1e293b" gap={24} />
          <Controls className="!bg-slate-800 !border-slate-700" />
          <MiniMap
            className="!bg-slate-900 !border-slate-700"
            nodeColor={(n) => {
              const d = n.data as { hasRisk?: boolean; privilege?: string };
              if (d.hasRisk) return '#ef4444';
              if (d.privilege === 'ADMIN') return '#ef4444';
              if (d.privilege === 'SERVICE' || d.privilege === 'ELEVATED') return '#8b5cf6';
              if (d.privilege === 'USER') return '#3b82f6';
              return '#475569';
            }}
          />
        </ReactFlow>
      </div>

      {/* Inspector Panel */}
      {selectedService && (
        <div className="w-80 bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-y-auto">
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-blue-400" />
            <span className="text-slate-200 font-semibold text-sm">{selectedService.name}</span>
          </div>

          <div className="space-y-3 mb-4">
            <div className="flex justify-between text-sm">
              <span className="text-slate-500">Privilege</span>
              <span className="text-slate-300">{selectedService.privilege_level}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-500">Confidence</span>
              <span className="text-slate-300">{selectedService.confidence}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-500">Path</span>
              <span className="text-slate-300 font-mono text-xs">{selectedService.path}</span>
            </div>
          </div>

          {selectedEndpoints.length > 0 && (
            <div className="mb-4">
              <div className="text-slate-500 text-xs font-medium uppercase mb-2">Endpoints</div>
              <div className="space-y-1.5">
                {selectedEndpoints.map(ep => (
                  <div key={ep.endpoint_id} className={`
                    flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs
                    ${ep.is_sensitive ? 'bg-amber-500/5 border border-amber-500/20' : 'bg-slate-800'}
                  `}>
                    <span className={`font-mono font-bold ${
                      ep.method === 'DELETE' ? 'text-red-400' :
                      ep.method === 'POST' ? 'text-blue-400' :
                      ep.method === 'GET' ? 'text-emerald-400' : 'text-amber-400'
                    }`}>{ep.method}</span>
                    <span className="text-slate-400 truncate font-mono">{ep.route}</span>
                    {ep.is_sensitive && <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />}
                  </div>
                ))}
              </div>
            </div>
          )}

          {selectedFindings.length > 0 && (
            <div>
              <div className="text-slate-500 text-xs font-medium uppercase mb-2">Related Findings</div>
              <div className="space-y-2">
                {selectedFindings.map(f => (
                  <div key={f.finding_id} className="p-2 bg-red-500/5 border border-red-500/20 rounded-lg">
                    <div className="text-red-400 text-xs font-semibold">{f.rule_id}</div>
                    <div className="text-slate-400 text-xs mt-0.5">{f.title}</div>
                    <div className="flex gap-1 mt-1">
                      <span className="text-xs px-1.5 py-0.5 bg-red-500/10 text-red-400 rounded">{f.severity}</span>
                      <span className="text-xs px-1.5 py-0.5 bg-slate-700 text-slate-400 rounded">{f.confidence}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
