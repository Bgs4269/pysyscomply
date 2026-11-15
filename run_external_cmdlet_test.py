import os
import sys
from pathlib import Path

from pysyscomply import CMDLET_REGISTRY, ComplianceBenchmarkAuditor


def main() -> int:
    project_dir = Path(__file__).resolve().parent
    testbook_path = project_dir / "testbooks" / "external-cmdlet-test.json"
    cmdlet_path = project_dir / "testbooks" / "external_cmdlet.py"

    CMDLET_REGISTRY["extcmdlet"] = ("external", str(cmdlet_path))

    with ComplianceBenchmarkAuditor(
        [str(testbook_path)],
        log_file_name=os.devnull,
    ) as auditor:
        return auditor.run()


if __name__ == "__main__":
    sys.exit(main())
