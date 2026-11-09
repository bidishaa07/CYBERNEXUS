"""Vercel entrypoint for the backend service.

Vercel builds this service with ``backend`` as its working root.  The
application itself keeps the repository-root import path (``backend.app``)
for local, Docker, and test execution, so this small adapter exposes that
package name when the service root is the backend directory.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parent
service_root = str(SERVICE_ROOT)
if service_root not in sys.path:
    sys.path.insert(0, service_root)

backend_package = types.ModuleType("backend")
backend_package.__path__ = [service_root]
sys.modules.setdefault("backend", backend_package)
sys.modules.setdefault("backend.app", importlib.import_module("app"))

from app.main import app

__all__ = ["app"]
