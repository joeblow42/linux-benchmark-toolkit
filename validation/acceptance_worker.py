"""Execute exactly one legacy Phase 1 acceptance check in an isolated process.

Internal adapter protocol. Not a supported operator CLI. Worker stdout is a
small machine-readable JSON outcome and does not contain subprocess logs.
"""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(json.dumps({"status": "FAIL", "reason": "invalid worker invocation"}))
        return 2
    root = Path(args[0]).resolve()
    try:
        index = int(args[1])
        if not 1 <= index <= 16 or index == 2:
            raise ValueError("worker index must reference a non-unit Phase 1 check")
        path = root / "tests" / "acceptance_phase1.py"
        spec = importlib.util.spec_from_file_location("_lbt_worker_acceptance", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("acceptance module cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if len(module.CHECKS) != 16:
            raise RuntimeError("original acceptance check count has changed")
        with tempfile.TemporaryDirectory(prefix="lbt-worker-") as workspace:
            try:
                module.CHECKS[index - 1][1](root, Path(workspace))
                response = {"status": "PASS", "reason": ""}
            except module.SkipCheck as error:
                response = {"status": "SKIP", "reason": str(error)}
    except Exception as error:
        response = {"status": "FAIL", "reason": f"{type(error).__name__}: {error}"}
    print(json.dumps(response, ensure_ascii=True))
    return 0 if response["status"] in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
