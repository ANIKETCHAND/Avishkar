import os
import sys
from pathlib import Path

# Add project root and backend directory to sys.path
current_dir = Path(__file__).resolve().parent
root_dir = current_dir.parent
backend_dir = root_dir / "backend"

for p in [str(backend_dir), str(root_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Serverless environments on Vercel require temporary directories under /tmp
os.environ.setdefault("SCAN_STORAGE_DIR", "/tmp/scans")
os.environ.setdefault("VERCEL", "1")

from app.main import app
