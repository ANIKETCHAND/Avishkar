"""
Analysis Orchestrator — Risk Engine
=====================================
Orchestrates the complete static analysis pipeline:
1. ZIP ingestion
2. AST parsing
3. Service discovery
4. Endpoint discovery
5. Service call discovery
6. Auth/privilege analysis
7. Graph construction
8. Detection rules (CD-001..CD-004)
9. Summary stats
10. ScanResult assembly

This is the single entry point for the analysis pipeline.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..analyzer import (
    analyze_files, discover_services, discover_endpoints,
    discover_service_calls, analyze_privilege_boundaries,
    refine_service_privileges,
)
from ..graph.call_graph import CallGraph
from ..rules.detection_engine import run_all_rules
from ..models.schemas import (
    Project, Service, Endpoint, ServiceCall, PrivilegeBoundary,
    Finding, GraphModel, ScanResult,
    STATUS_COMPLETED, STATUS_FAILED, STATUS_PROCESSING,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)

logger = logging.getLogger(__name__)


def run_analysis(
    python_files: List[Path],
    workspace_root: Path,
    project_name: str,
    scan_id: str,
) -> ScanResult:
    """
    Execute the complete confused deputy static analysis pipeline.

    Args:
        python_files: List of Python files to analyze.
        workspace_root: Root of the extracted workspace.
        project_name: Name of the uploaded project.
        scan_id: Unique scan identifier.

    Returns:
        Complete ScanResult with all findings, graph, and metadata.
    """
    start_time = time.monotonic()
    logger.info("Starting analysis for scan %s (%d Python files)", scan_id, len(python_files))

    project = Project(
        project_id=f"proj_{scan_id[:8]}",
        project_name=project_name,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
        scan_status=STATUS_PROCESSING,
        total_files=len(python_files),
    )

    warnings: List[str] = []

    try:
        # ── Step 1: AST Parsing ───────────────────────────────────────────────
        logger.info("Step 1/7: AST parsing...")
        ast_results, parse_errors = analyze_files(python_files, workspace_root)
        for err in parse_errors:
            warnings.append(f"Parse error in {err['file']}: {err['error']}")

        # ── Step 2: Service Discovery ─────────────────────────────────────────
        logger.info("Step 2/7: Service discovery...")
        services = discover_services(ast_results, workspace_root)

        if not services:
            logger.warning("No services discovered. Check if uploaded project contains FastAPI code.")
            warnings.append("No FastAPI services discovered in the uploaded project.")

        # ── Step 3: Endpoint Discovery ────────────────────────────────────────
        logger.info("Step 3/7: Endpoint discovery...")
        endpoints = discover_endpoints(ast_results, services, workspace_root)

        # ── Step 4: Service Call Discovery ───────────────────────────────────
        logger.info("Step 4/7: Service call discovery...")
        service_calls = discover_service_calls(ast_results, services, endpoints)

        # ── Step 5: Auth/Privilege Refinement ────────────────────────────────
        logger.info("Step 5/7: Authorization & privilege analysis...")
        services = refine_service_privileges(services, endpoints)
        privilege_boundaries = analyze_privilege_boundaries(services, service_calls)

        # ── Step 6: Graph Construction ────────────────────────────────────────
        logger.info("Step 6/7: Call graph construction...")
        call_graph = CallGraph()
        call_graph.build(services, endpoints, service_calls)

        # ── Step 7: Detection Rules ───────────────────────────────────────────
        logger.info("Step 7/7: Running detection rules CD-001..CD-004...")
        findings = run_all_rules(call_graph, services, endpoints, service_calls)

        # ── Serialize Graph ───────────────────────────────────────────────────
        graph_model = call_graph.to_graph_model()

        # Update graph nodes with risk flags from findings
        risky_service_ids = {f.source_service_id for f in findings} | {f.destination_service_id for f in findings}
        for node in graph_model.nodes:
            if node.id in risky_service_ids:
                node.data["hasRisk"] = True

        # Update graph edges with severity from findings
        finding_by_src_dst = {}
        for f in findings:
            key = (f.source_service_id, f.destination_service_id)
            if key not in finding_by_src_dst or _severity_rank(f.severity) > _severity_rank(finding_by_src_dst[key].severity):
                finding_by_src_dst[key] = f

        for edge in graph_model.edges:
            key = (edge.source, edge.target)
            if key in finding_by_src_dst:
                edge.data["risk"] = True
                edge.data["severity"] = finding_by_src_dst[key].severity
                edge.data["riskRule"] = finding_by_src_dst[key].rule_id

        # ── Summary Stats ─────────────────────────────────────────────────────
        summary_stats = _compute_summary_stats(findings, services, endpoints, service_calls)

        # ── Finalize ──────────────────────────────────────────────────────────
        duration = time.monotonic() - start_time
        project = project.model_copy(update={
            "scan_status": STATUS_COMPLETED,
            "total_files": len(python_files),
        })

        scan_result = ScanResult(
            scan_id=scan_id,
            project=project,
            services=services,
            endpoints=endpoints,
            service_calls=service_calls,
            privilege_boundaries=privilege_boundaries,
            graph=graph_model,
            findings=findings,
            summary_stats=summary_stats,
            scan_duration_seconds=round(duration, 3),
            warnings=warnings,
        )

        logger.info(
            "Analysis complete: %d services, %d endpoints, %d calls, %d findings in %.2fs",
            len(services), len(endpoints), len(service_calls), len(findings), duration,
        )

        return scan_result

    except Exception as exc:
        duration = time.monotonic() - start_time
        logger.error("Analysis failed: %s", exc, exc_info=True)

        project = project.model_copy(update={"scan_status": STATUS_FAILED})

        return ScanResult(
            scan_id=scan_id,
            project=project,
            warnings=[f"Analysis failed: {exc}"] + warnings,
            scan_duration_seconds=round(duration, 3),
        )


def _severity_rank(severity: str) -> int:
    """Numeric rank for severity comparison."""
    return {SEVERITY_CRITICAL: 4, SEVERITY_HIGH: 3, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 1}.get(severity, 0)


def _compute_summary_stats(
    findings: List[Finding],
    services: List[Service],
    endpoints: List[Endpoint],
    service_calls: List[ServiceCall],
) -> Dict[str, int]:
    """Compute summary statistics for the scan result."""
    stats = {
        "critical": sum(1 for f in findings if f.severity == SEVERITY_CRITICAL),
        "high": sum(1 for f in findings if f.severity == SEVERITY_HIGH),
        "medium": sum(1 for f in findings if f.severity == SEVERITY_MEDIUM),
        "low": sum(1 for f in findings if f.severity == SEVERITY_LOW),
        "total_findings": len(findings),
        "total_services": len(services),
        "total_endpoints": len(endpoints),
        "total_service_calls": len(service_calls),
        "cd001": sum(1 for f in findings if f.rule_id == "CD-001"),
        "cd002": sum(1 for f in findings if f.rule_id == "CD-002"),
        "cd003": sum(1 for f in findings if f.rule_id == "CD-003"),
        "cd004": sum(1 for f in findings if f.rule_id == "CD-004"),
    }
    return stats
