"""
Demo ZIP Generator
==================
Packages demo/vulnerable and demo/secure into ZIP archives for direct upload testing.
"""

import sys
import zipfile
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent

def package_dir(source_dir: Path, output_zip: Path):
    if not source_dir.exists():
        print(f"Error: {source_dir} does not exist", file=sys.stderr)
        return
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in source_dir.rglob("*.py"):
            if "__pycache__" in str(file_path):
                continue
            rel_name = file_path.relative_to(source_dir)
            zf.write(file_path, arcname=str(rel_name))
    print(f"Created {output_zip} ({output_zip.stat().st_size} bytes)")

def main():
    package_dir(DEMO_DIR / "vulnerable", DEMO_DIR / "vulnerable.zip")
    package_dir(DEMO_DIR / "secure", DEMO_DIR / "secure.zip")
    print("Demo packages ready.")

if __name__ == "__main__":
    main()
