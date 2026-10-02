"""
NetworkX Call Graph Builder — Phase 6
=======================================
Constructs a directed NetworkX DiGraph from discovered services,
endpoints, and service calls. The graph is used for:
- Path tracing (all paths from entry points to downstream services)
- CD-001 through CD-004 rule evaluation
- React Flow visualization serialization

Node types:
- SERVICE_NODE: A microservice boundary
- ENDPOINT_NODE: A specific HTTP route handler

Edge metadata includes:
- call type (HTTP_CLIENT)
- identity propagation classification
- risk flags from detected patterns
- source file and line

SECURITY: Never executes uploaded code.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

import networkx as nx

from ..models.schemas import (
    Service, Endpoint, ServiceCall,
    GraphNode, GraphEdge, GraphModel,
    PRIVILEGE_RANK,
)

logger = logging.getLogger(__name__)

# ─────────────────────────── Node Attribute Keys ─────────────────────────

NODE_TYPE_SERVICE = "SERVICE_NODE"
NODE_TYPE_ENDPOINT = "ENDPOINT_NODE"


class CallGraph:
    """
    Directed NetworkX call graph representing the microservices topology.

    Nodes: services and endpoints
    Edges: inter-service HTTP calls
    """

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._services: Dict[str, Service] = {}
        self._endpoints: Dict[str, Endpoint] = {}
        self._service_calls: List[ServiceCall] = []

    # ── Graph Population ─────────────────────────────────────────────────

    def build(
        self,
        services: List[Service],
        endpoints: List[Endpoint],
        service_calls: List[ServiceCall],
    ) -> None:
        """
        Populate the graph from discovered components.

        Args:
            services: Discovered services.
            endpoints: Discovered endpoints.
            service_calls: Discovered inter-service calls.
        """
        self._services = {s.service_id: s for s in services}
        self._endpoints = {e.endpoint_id: e for e in endpoints}
        self._service_calls = service_calls

        # Add service nodes
        for service in services:
            ep_count = sum(1 for e in endpoints if e.service_id == service.service_id)
            self.graph.add_node(
                service.service_id,
                node_type=NODE_TYPE_SERVICE,
                label=service.name,
                privilege=service.privilege_level,
                confidence=service.confidence,
                path=service.path,
                endpoint_count=ep_count,
                entry_points=service.entry_points,
            )

        # Add endpoint nodes
        for ep in endpoints:
            self.graph.add_node(
                ep.endpoint_id,
                node_type=NODE_TYPE_ENDPOINT,
                label=f"{ep.method} {ep.route}",
                service_id=ep.service_id,
                method=ep.method,
                route=ep.route,
                handler=ep.handler,
                file=ep.file,
                line_start=ep.line_start,
                line_end=ep.line_end,
                authenticated=ep.authentication,
                authorization_checks=ep.authorization_checks,
                is_sensitive=ep.is_sensitive,
            )
            # Connect endpoint to its service
            self.graph.add_edge(
                ep.service_id,
                ep.endpoint_id,
                edge_type="CONTAINS",
                label="contains",
            )

        # Add inter-service call edges
        for call in service_calls:
            src = call.source_service_id
            dst = call.destination_service_id

            if src not in self.graph or dst not in self.graph:
                logger.debug(
                    "Skipping call edge %s -> %s (one or both nodes missing)",
                    src, dst,
                )
                continue

            # Check for privilege escalation
            src_service = self._services.get(src)
            dst_service = self._services.get(dst)
            privilege_escalation = False
            if src_service and dst_service:
                src_rank = PRIVILEGE_RANK.get(src_service.privilege_level, -1)
                dst_rank = PRIVILEGE_RANK.get(dst_service.privilege_level, -1)
                privilege_escalation = dst_rank > src_rank > 0

            self.graph.add_edge(
                src,
                dst,
                edge_id=call.call_id,
                edge_type="SERVICE_CALL",
                label=f"{call.http_method} {call.destination_route}",
                http_method=call.http_method,
                destination_route=call.destination_route,
                call_type=call.call_type,
                identity_propagation=call.identity_propagation,
                passed_headers=call.passed_headers,
                source_file=call.source_file,
                source_line=call.source_line,
                source_endpoint_id=call.source_endpoint_id,
                privilege_escalation=privilege_escalation,
                risk=False,   # Updated by detection engine
                risk_rule=None,
            )

        logger.info(
            "Call graph built: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

    # ── Graph Query Utilities ────────────────────────────────────────────

    def get_service_nodes(self) -> List[str]:
        """Return all service node IDs."""
        return [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == NODE_TYPE_SERVICE
        ]

    def get_endpoint_nodes(self) -> List[str]:
        """Return all endpoint node IDs."""
        return [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == NODE_TYPE_ENDPOINT
        ]

    def get_service_call_edges(self) -> List[Tuple[str, str, Dict]]:
        """Return all inter-service call edges."""
        return [
            (u, v, d)
            for u, v, d in self.graph.edges(data=True)
            if d.get("edge_type") == "SERVICE_CALL"
        ]

    def get_all_paths_between_services(
        self,
        source_service: str,
        target_service: str,
    ) -> List[List[str]]:
        """
        Find all simple directed paths between two service nodes.
        Returns list of paths (each path is a list of node IDs).
        """
        try:
            paths = list(nx.all_simple_paths(
                self.graph, source_service, target_service, cutoff=10
            ))
            return paths
        except (nx.NetworkXError, nx.NodeNotFound):
            return []

    def is_reachable_from_public(
        self,
        node_id: str,
        user_privilege_levels: frozenset = frozenset({"PUBLIC", "USER"}),
    ) -> bool:
        """
        Check if a node is reachable from any public/user-facing service node.
        """
        for service_id, data in self.graph.nodes(data=True):
            if data.get("node_type") != NODE_TYPE_SERVICE:
                continue
            priv = data.get("privilege", "UNKNOWN")
            if priv not in user_privilege_levels:
                continue
            try:
                if nx.has_path(self.graph, service_id, node_id):
                    return True
            except (nx.NetworkXError, nx.NodeNotFound):
                continue
        return False

    def get_endpoints_for_service(self, service_id: str) -> List[Endpoint]:
        """Get all endpoint objects for a given service."""
        return [ep for ep in self._endpoints.values() if ep.service_id == service_id]

    def get_downstream_services(self, service_id: str) -> List[str]:
        """Get all services reachable from the given service (direct successors only)."""
        return [
            n for n in self.graph.successors(service_id)
            if self.graph.nodes[n].get("node_type") == NODE_TYPE_SERVICE
        ]

    def mark_edge_as_risky(self, src: str, dst: str, rule_id: str) -> None:
        """Mark a service call edge as risky for visualization."""
        if self.graph.has_edge(src, dst):
            self.graph[src][dst]["risk"] = True
            self.graph[src][dst]["risk_rule"] = rule_id

    # ── Serialization ────────────────────────────────────────────────────

    def to_graph_model(self) -> GraphModel:
        """
        Serialize the graph to React Flow-compatible GraphModel.

        Returns:
            GraphModel with nodes and edges for frontend rendering.
        """
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        # Serialize nodes
        for node_id, data in self.graph.nodes(data=True):
            node_type = data.get("node_type", NODE_TYPE_SERVICE)

            if node_type == NODE_TYPE_SERVICE:
                node_data = {
                    "privilege": data.get("privilege", "UNKNOWN"),
                    "confidence": data.get("confidence", "LOW"),
                    "endpointsCount": data.get("endpoint_count", 0),
                    "path": data.get("path", ""),
                    "entryPoints": data.get("entry_points", []),
                    "hasRisk": False,  # Updated after detection
                }
            else:
                node_data = {
                    "serviceId": data.get("service_id", ""),
                    "method": data.get("method", ""),
                    "route": data.get("route", ""),
                    "handler": data.get("handler", ""),
                    "file": data.get("file", ""),
                    "lineStart": data.get("line_start", 0),
                    "lineEnd": data.get("line_end", 0),
                    "authenticated": data.get("authenticated", False),
                    "authorizationChecks": data.get("authorization_checks", []),
                    "isSensitive": data.get("is_sensitive", False),
                }

            nodes.append(GraphNode(
                id=node_id,
                label=data.get("label", node_id),
                type=node_type,
                data=node_data,
            ))

        # Serialize edges (only SERVICE_CALL edges for the React Flow graph)
        for u, v, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type", "")
            if edge_type != "SERVICE_CALL":
                continue

            edge_data = {
                "callType": data.get("call_type", "HTTP_CLIENT"),
                "identityPropagation": data.get("identity_propagation", "UNKNOWN"),
                "passedHeaders": data.get("passed_headers", []),
                "sourceFile": data.get("source_file", ""),
                "sourceLine": data.get("source_line", 0),
                "privilegeEscalation": data.get("privilege_escalation", False),
                "risk": data.get("risk", False),
                "riskRule": data.get("risk_rule"),
                "severity": None,  # Updated after detection
            }

            edges.append(GraphEdge(
                id=data.get("edge_id", f"edge_{u}_{v}"),
                source=u,
                target=v,
                label=data.get("label", ""),
                data=edge_data,
            ))

        return GraphModel(nodes=nodes, edges=edges)
