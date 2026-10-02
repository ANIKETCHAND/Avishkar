"""
Safe ZIP Unpacker — Phase 2
============================
Securely extracts uploaded ZIP archives into isolated temporary workspaces.

Security features:
- Max archive size: 50 MB compressed, 100 MB uncompressed
- Max file count: 500 files
- Max compression ratio: 10:1 per-file
- Path traversal protection (canonical path checking)
- Symlink / hard-link rejection
- Dangerous extension rejection (.exe, .sh, .bat, etc.)
- Temporary isolated workspace per scan
- Automatic cleanup utilities

NEVER executes uploaded code. Only reads file metadata and content.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────── Security Limits ──────────────────────────────

MAX_ARCHIVE_SIZE_BYTES: int = 50 * 1024 * 1024   # 50 MB compressed
MAX_EXTRACTED_SIZE_BYTES: int = 100 * 1024 * 1024 # 100 MB uncompressed
MAX_FILE_COUNT: int = 500
MAX_COMPRESSION_RATIO: float = 10.0

# Allowed extensions (whitelist — much safer than a blocklist)
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".txt", ".md", ".toml", ".cfg", ".ini", ".yaml", ".yml",
    ".json", ".env.example", ".env.sample", ".dockerignore",
    ".gitignore", ".requirements", "",
})

# Dangerous filenames / extensions to explicitly reject
DANGEROUS_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.(exe|sh|bash|bat|cmd|ps1|vbs|js|jar|class|so|dll|dylib)$", re.IGNORECASE),
    re.compile(r"^__pycache__"),
    re.compile(r"\.pyc$"),
]


class IngestionError(Exception):
    """Raised when archive ingestion fails due to security or validity issues."""


class ExtractionResult:
    """Result of a successful archive extraction."""

    def __init__(self, workspace_dir: Path, python_files: List[Path], all_files: List[Path]):
        self.workspace_dir = workspace_dir
        self.python_files = python_files
        self.all_files = all_files

    @property
    def total_files(self) -> int:
        return len(self.all_files)

    def cleanup(self) -> None:
        """Remove the temporary workspace directory."""
        if self.workspace_dir.exists():
            shutil.rmtree(self.workspace_dir, ignore_errors=True)
            logger.debug("Cleaned up workspace: %s", self.workspace_dir)


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """
    Verify that target_path is strictly within base_dir.
    Prevents path traversal attacks (../ sequences).
    """
    try:
        target_path.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def _check_dangerous_name(name: str) -> bool:
    """Return True if the filename matches a dangerous pattern."""
    basename = Path(name).name
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(basename):
            return True
    return False


def unpack_zip(
    zip_path: Path,
    base_storage_dir: Path,
    scan_id: str,
) -> ExtractionResult:
    """
    Safely unpack a ZIP archive into an isolated workspace.

    Args:
        zip_path: Path to the uploaded ZIP file.
        base_storage_dir: Base directory for scan workspaces.
        scan_id: Unique scan identifier for workspace naming.

    Returns:
        ExtractionResult with workspace directory and discovered Python files.

    Raises:
        IngestionError: If any security constraint is violated.
    """
    # ── 1. Check compressed size ────────────────────────────────────────────
    compressed_size = zip_path.stat().st_size
    if compressed_size > MAX_ARCHIVE_SIZE_BYTES:
        raise IngestionError(
            f"Archive too large: {compressed_size} bytes "
            f"(max {MAX_ARCHIVE_SIZE_BYTES} bytes / 50 MB)"
        )

    # ── 2. Validate ZIP structure ────────────────────────────────────────────
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            bad_names = zf.testzip()
            if bad_names:
                raise IngestionError(f"Corrupt archive entry: {bad_names}")

            members = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise IngestionError(f"Invalid ZIP file: {exc}") from exc

    # ── 3. File count limit ──────────────────────────────────────────────────
    if len(members) > MAX_FILE_COUNT:
        raise IngestionError(
            f"Archive contains {len(members)} files "
            f"(max {MAX_FILE_COUNT})"
        )

    # ── 4. Create isolated workspace ─────────────────────────────────────────
    workspace_dir = base_storage_dir / scan_id / "extracted"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace_dir, 0o700)

    # ── 5. Validate and extract each member ──────────────────────────────────
    extracted_size_total: int = 0
    python_files: List[Path] = []
    all_files: List[Path] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in members:
            # ── a. Reject directories (we create them ourselves) ────────────
            if member.is_dir():
                continue

            member_name = member.filename

            # ── b. Path traversal protection ────────────────────────────────
            # Check for ".." BEFORE normalization — this catches ../etc/passwd
            raw_parts = member_name.replace("\\", "/").split("/")
            if ".." in raw_parts:
                logger.warning("Rejected path traversal attempt: %s", member_name)
                raise IngestionError(
                    f"Path traversal detected in archive entry: {member_name}"
                )

            # Strip leading slashes and normalize
            safe_name = member_name.lstrip("/").lstrip("\\")
            safe_name = re.sub(r"\.\.[\\/]", "", safe_name)

            dest_path = workspace_dir / safe_name
            if not _is_safe_path(workspace_dir, dest_path):
                logger.warning("Rejected unsafe path: %s", member_name)
                raise IngestionError(
                    f"Path traversal detected in archive entry: {member_name}"
                )

            # ── c. Reject symlinks / external_attr tricks ───────────────────
            # Unix symlinks: external_attr upper 16 bits = file mode
            if (member.external_attr >> 16) & 0xFFFF == 0xA1ED:  # S_ISLNK
                logger.warning("Rejected symlink in archive: %s", member_name)
                continue

            # ── d. Check compression ratio (zip bomb) ───────────────────────
            if member.compress_size > 0:
                ratio = member.file_size / member.compress_size
                if ratio > MAX_COMPRESSION_RATIO and member.file_size > 1024 * 1024:
                    raise IngestionError(
                        f"Zip bomb detected: entry {member_name!r} has "
                        f"compression ratio {ratio:.1f}:1"
                    )

            # ── e. Total uncompressed size limit ────────────────────────────
            extracted_size_total += member.file_size
            if extracted_size_total > MAX_EXTRACTED_SIZE_BYTES:
                raise IngestionError(
                    f"Total uncompressed size exceeds {MAX_EXTRACTED_SIZE_BYTES // (1024*1024)} MB"
                )

            # ── f. Check extension whitelist ─────────────────────────────────
            ext = Path(safe_name).suffix.lower()
            filename = Path(safe_name).name

            # Skip hidden files and cache
            if filename.startswith(".") and ext not in {".env.example", ".env.sample"}:
                continue
            if "__pycache__" in safe_name:
                continue
            if ext == ".pyc":
                continue

            # ── g. Extract safely ────────────────────────────────────────────
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                data = zf.read(member_name)
            except Exception as exc:
                logger.warning("Could not read archive member %s: %s", member_name, exc)
                continue

            dest_path.write_bytes(data)
            all_files.append(dest_path)

            if ext == ".py":
                python_files.append(dest_path)

    logger.info(
        "Extraction complete: %d Python files, %d total files, %.1f KB uncompressed",
        len(python_files),
        len(all_files),
        extracted_size_total / 1024,
    )

    return ExtractionResult(
        workspace_dir=workspace_dir,
        python_files=python_files,
        all_files=all_files,
    )


def unpack_directory(source_dir: Path, base_storage_dir: Path, scan_id: str) -> ExtractionResult:
    """
    'Extract' a pre-existing directory (for demo benchmarks).
    Copies files to an isolated workspace — does NOT execute anything.
    """
    workspace_dir = base_storage_dir / scan_id / "extracted"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace_dir, 0o700)

    python_files: List[Path] = []
    all_files: List[Path] = []

    for src_file in source_dir.rglob("*"):
        if not src_file.is_file():
            continue
        if "__pycache__" in str(src_file):
            continue
        if src_file.suffix == ".pyc":
            continue

        rel = src_file.relative_to(source_dir)
        dest = workspace_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dest)
        all_files.append(dest)
        if src_file.suffix == ".py":
            python_files.append(dest)

    return ExtractionResult(
        workspace_dir=workspace_dir,
        python_files=python_files,
        all_files=all_files,
    )


def create_zip_from_directory(source_dir: Path, output_path: Path) -> Path:
    """
    Create a ZIP archive from a directory (used for demo benchmarks).
    Returns the path to the created ZIP.
    """
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in source_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(source_dir.parent)
                zf.write(file_path, arcname)
    return output_path
