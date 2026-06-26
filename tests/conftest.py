"""Import setup for the test suite.

Adds the repository root to ``sys.path`` so the pipeline stages under
``scripts/`` can be imported as ``scripts.<module>`` without installing the
project. The tests target the pandas fallback and the pure scoring logic, so
no Spark session is required.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
