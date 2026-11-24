"""Every test run uses its own throwaway database, so tests never touch data/raqeeb.db."""
import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="raqeeb-test-"))
os.environ["SAWNN_DB"] = str(_tmp / "test.db")
os.environ["SAWNN_ADMIN_PASSWORD"] = "test-admin-password"
# Background threads stay off in tests; tests drive the orchestrator and scheduler explicitly.
os.environ["SAWNN_SCHEDULER_ENABLED"] = "0"
os.environ["SAWNN_ORCHESTRATOR"] = "1"
os.environ["SAWNN_WORKER"] = "0"
