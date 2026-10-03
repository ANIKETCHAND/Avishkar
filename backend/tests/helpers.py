"""
Benchmark and Test Helper Utilities
=====================================
Provides lightweight orchestration to run the static analysis pipeline
on in-memory source files for benchmark matrices and property tests.
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Iterable, List, Set, Tuple

from app.analyzer.ast_visitor import analyze_files
from app.analyzer.service_discovery import discover_services
from app.analyzer.api_discovery import discover_endpoints, discover_service_calls
from app.analyzer.auth_analyzer import analyze_privilege_boundaries, refine_service_privileges
from app.graph.call_graph import CallGraph
from app.rules.detection_engine import run_all_rules
from app.models.schemas import ScanResult, Project, STATUS_COMPLETED


@dataclass(frozen=True)
class RuleComparisonResult:
    """Structured result of comparing expected vs actual detected security rules."""
    exact_match: bool
    missing_rules: List[str]
    unexpected_rules: List[str]
    classification: str  # "TP", "TN", "FP", "FN", "MIXED"
    expected_rules: List[str]
    actual_rules: List[str]

    @property
    def status_label(self) -> str:
        if self.exact_match:
            return "TP (PASS)" if self.classification == "TP" else "TN (PASS)"
        if self.classification == "MIXED":
            return "MIXED-ERROR"
        if self.classification == "FP":
            return "RULE-MISMATCH / FALSE-POSITIVE"
        if self.classification == "FN":
            return "FALSE-NEGATIVE"
        return "FAIL"

    @property
    def status(self) -> str:
        return self.status_label

    def format_details(self, case_name: str) -> str:
        return (
            f"Case: {case_name}\n"
            f"Expected: {self.expected_rules}\n"
            f"Actual: {self.actual_rules}\n"
            f"Missing: {self.missing_rules}\n"
            f"Unexpected: {self.unexpected_rules}\n"
            f"Status: {self.status_label}"
        )


def compare_expected_actual_rules(
    expected_rules: Iterable[str],
    actual_rules: Iterable[str],
) -> RuleComparisonResult:
    """
    Perform exact set comparison between expected rules and actual detected rules.
    Guarantees deterministic sorted outputs and formal error classification.
    """
    exp_set = set(expected_rules)
    act_set = set(actual_rules)

    missing = sorted(list(exp_set - act_set))
    unexpected = sorted(list(act_set - exp_set))
    exact_match = (exp_set == act_set)

    is_expected_vulnerable = len(exp_set) > 0

    if exact_match:
        classification = "TP" if is_expected_vulnerable else "TN"
    else:
        if missing and unexpected:
            classification = "MIXED"
        elif unexpected:
            classification = "FP"
        else:
            classification = "FN"

    return RuleComparisonResult(
        exact_match=exact_match,
        missing_rules=missing,
        unexpected_rules=unexpected,
        classification=classification,
        expected_rules=sorted(list(exp_set)),
        actual_rules=sorted(list(act_set)),
    )



def analyze_test_project(files: Dict[str, str], tmp_path: Path, project_name: str = "test-project") -> ScanResult:
    """Write dictionary of files to tmp_path and run complete analysis pipeline."""
    workspace = tmp_path / project_name
    workspace.mkdir(parents=True, exist_ok=True)

    py_files: List[Path] = []
    for rel_path, code in files.items():
        file_path = workspace / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(code, encoding="utf-8")
        if file_path.suffix == ".py":
            py_files.append(file_path)

    ast_results, parse_errors = analyze_files(py_files, workspace)
    services = discover_services(ast_results, workspace)
    endpoints = discover_endpoints(ast_results, services, workspace)
    service_calls = discover_service_calls(ast_results, services, endpoints)

    services = refine_service_privileges(services, endpoints)
    privilege_boundaries = analyze_privilege_boundaries(services, service_calls)

    cg = CallGraph()
    cg.build(services, endpoints, service_calls)

    findings = run_all_rules(cg, services, endpoints, service_calls)
    graph_model = cg.to_graph_model()

    project = Project(
        project_name=project_name,
        uploaded_at="2026-10-02T00:00:00Z",
        total_files=len(py_files),
        scan_status=STATUS_COMPLETED,
    )

    return ScanResult(
        scan_id=f"scan_{project_name}",
        project=project,
        services=services,
        endpoints=endpoints,
        service_calls=service_calls,
        privilege_boundaries=privilege_boundaries,
        graph=graph_model,
        findings=findings,
        summary_stats={
            "total_findings": len(findings),
            "cd001": sum(1 for f in findings if f.rule_id == "CD-001"),
            "cd002": sum(1 for f in findings if f.rule_id == "CD-002"),
            "cd003": sum(1 for f in findings if f.rule_id == "CD-003"),
            "cd004": sum(1 for f in findings if f.rule_id == "CD-004"),
        },
    )
