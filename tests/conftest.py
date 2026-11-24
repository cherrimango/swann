"""Every test run uses its own throwaway database, so tests never touch data/raqeeb.db."""
import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="raqeeb-test-"))
os.environ["RAQEEB_DB"] = str(_tmp / "test.db")
os.environ["RAQEEB_ADMIN_PASSWORD"] = "test-admin-password"
