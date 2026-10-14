"""Shared real-Qt helpers for headless regression tests."""

import os
from pathlib import Path
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtCore import QSettings
from gui import application

SETTINGS_DIRECTORY = tempfile.TemporaryDirectory()
APP = application(QSettings(str(Path(SETTINGS_DIRECTORY.name) / "appearance.ini"), QSettings.Format.IniFormat))


def wait_until(predicate, timeout=5):
    """Process Qt events until an asynchronous condition is met, with a strict deadline."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if predicate():
            return
        QTest.qWait(10)
    raise AssertionError("Qt condition did not complete before the deadline")
