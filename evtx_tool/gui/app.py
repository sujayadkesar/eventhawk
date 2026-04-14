"""
EventHawk — GUI entry point.

Usage:
    py -3 evtx_tool.py gui
    py -3 evtx_tool.py gui D:\\Logs
    py -3 evtx_tool.py gui D:\\Logs\\Security.evtx
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler


def _setup_gui_logging() -> None:
    """Configure root logger for the GUI process.

    Writes WARNING and above from every module to a rotating log file so
    errors surfaced in the GUI are always persisted to disk.  The file is
    kept small (5 MB × 3 backups = 15 MB max) so it never fills the disk.
    """
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "evtx_tool_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "eventhawk_gui.log")

    handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,   # 5 MB per file
        backupCount=3,               # keep 3 rotated backups
        encoding="utf-8",
    )
    handler.setLevel(logging.WARNING)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    # Avoid adding duplicate handlers if launch() is somehow called twice
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)

    # Catch unhandled exceptions that slip past Qt's event loop
    def _excepthook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logging.getLogger("eventhawk.unhandled").critical(
            "Unhandled exception:\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )

    sys.excepthook = _excepthook


def launch(initial_paths: list[str] | None = None) -> None:
    """
    Launch the PySide6 GUI. This must be called from the main process
    (after the multiprocessing spawn guard) so child processes spawned
    by ProcessPoolExecutor don't try to open windows.
    """
    _setup_gui_logging()

    # Required for frozen executables (PyInstaller) + ProcessPoolExecutor on Windows
    multiprocessing.freeze_support()

    # Boost GUI process priority so the Qt event loop always wins scheduling
    # against the BELOW_NORMAL worker subprocess.
    try:
        import psutil
        p = psutil.Process()
        if sys.platform == "win32":
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        # On Linux, lowering nice requires root — skip for GUI
    except Exception:
        pass  # psutil not installed — non-fatal

    # ── Windows taskbar icon fix ───────────────────────────────────────────
    # Without this, Windows groups the process under python.exe's icon.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "EventHawk.DFIR.App.1"
            )
        except Exception:
            pass

    from PySide6.QtCore import Qt, QCoreApplication
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon, QPixmap

    # High-DPI settings (must be set before QApplication creation)
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("EventHawk")
    app.setApplicationVersion("1.1")
    app.setOrganizationName("DFIR Tools")

    # ── Set application-level icon (taskbar + title bar) ──────────────────
    _logo = os.path.join(os.path.dirname(__file__), "..", "resources", "images", "eventhawk_logo.png")
    _logo = os.path.normpath(_logo)
    if os.path.isfile(_logo):
        from PySide6.QtGui import QImage, QPainter

        # New PNG already has proper alpha — load directly, no background removal needed.
        _img = QImage(_logo).convertToFormat(QImage.Format.Format_ARGB32)
        _base = QPixmap.fromImage(_img)

        _icon = QIcon()
        for _sz in (16, 24, 32, 48, 64, 128, 256):
            # Scale to 110% target so logo fills more of the square,
            # then center on the canvas — only a tiny sliver is clipped from sides
            _target = int(_sz * 1.3)
            _scaled = _base.scaled(
                _target, _target,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            _canvas = QPixmap(_sz, _sz)
            _canvas.fill(Qt.GlobalColor.transparent)
            _p = QPainter(_canvas)
            _p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            _p.drawPixmap((_sz - _scaled.width()) // 2, (_sz - _scaled.height()) // 2, _scaled)
            _p.end()
            _icon.addPixmap(_canvas)

        app.setWindowIcon(_icon)

    # Apply dark theme
    from .theme import apply_theme
    apply_theme(app)

    from .main_window import MainWindow
    window = MainWindow(initial_paths=initial_paths or [])
    window.show()

    sys.exit(app.exec())
