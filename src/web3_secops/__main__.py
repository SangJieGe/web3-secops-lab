"""Package entry point: ``python -m web3_secops``.

Exists so the package has one canonical invocation
(``python -m web3_secops --once``) while ``python -m web3_secops.main`` keeps
working — both are covered in ``tests/test_main.py``, because a documented
command that silently prints nothing is worse than no command at all.
"""

from __future__ import annotations

import sys

from .main import main

if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    try:
        code = main()
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
    sys.exit(code)
