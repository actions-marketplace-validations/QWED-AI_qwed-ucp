"""Middleware package for QWED-UCP."""

# Note: FastAPI middleware requires starlette which may not be installed
# Import will fail gracefully if dependencies not available

__all__ = []

try:
    from .fastapi import QWEDUCPMiddleware, create_verification_dependency
    __all__.extend(["QWEDUCPMiddleware", "create_verification_dependency"])
except ImportError:
    pass  # starlette not installed
