"""Executor implementations: the transport seam for AppTap.

Importing the concrete executors here would pull in subprocess machinery eagerly;
keep them lazy so ``import apptap`` stays cheap. Use the package-level lazy
exports (``apptap.LocalExecutor`` / ``apptap.AdbExecutor``) or import the
submodule directly.
"""

from apptap.executors.base import BackgroundProc, CmdResult, Executor

__all__ = ["Executor", "CmdResult", "BackgroundProc"]
