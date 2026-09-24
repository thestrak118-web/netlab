"""A single Qt application instance shared by every test module.

Qt permits only one application object per process, and a QCoreApplication
created first would leave the GUI tests without QWidget support.  Everything
therefore goes through `get_app()`, which always produces a QApplication on
the offscreen platform.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_app = None


def get_app():
    global _app
    if _app is not None:
        return _app
    from PySide6.QtWidgets import QApplication
    existing = QApplication.instance()
    if existing is not None:
        _app = existing
        return _app
    _app = QApplication([])
    try:
        from netlab.gui import theme
        _app.setStyleSheet(theme.STYLESHEET)
    except Exception:
        pass
    return _app
