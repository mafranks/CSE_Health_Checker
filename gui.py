"""Shared Qt widgets, styling, and serialized background work for the Health Checker."""

import logging
from functools import partial
from pathlib import Path
import sys

from PySide6.QtCore import QEvent, QObject, QRunnable, QThreadPool, Qt, Signal, Slot
from PySide6.QtGui import QFont, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QHeaderView, QHBoxLayout,
    QLabel, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

from themes import ThemeManager


def application(settings=None):
    """Create or reuse Qt with shared appearance, sizing, and source/frozen build icons."""
    app = QApplication.instance() or QApplication(sys.argv)
    if hasattr(app, "theme"):
        return app
    app.setApplicationName("Secure Endpoint Health Checker")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI" if sys.platform == "win32" else "Arial", 10))
    app.theme = ThemeManager(app, settings)
    resource_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    app.setWindowIcon(QIcon(str(resource_root / "amp-icon.ico")))
    return app


def text_label(text="", role=None, wrap=True):
    """Make selectable plain text that wraps long values rather than clipping them."""
    label = QLabel(str(text))
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse |
                                  Qt.TextInteractionFlag.TextSelectableByKeyboard)
    if role:
        label.setProperty("role", role)
    return label


def set_badge(label, text, tone="neutral"):
    """Render a readable status with both a text label and a semantic color."""
    label.setText(str(text))
    label.setProperty("role", "badge")
    label.setProperty("tone", tone)
    label.style().unpolish(label)
    label.style().polish(label)
    label.update()


def button(text, callback, primary=False):
    """Build a consistently sized action button with keyboard focus support."""
    widget = QPushButton(text)
    widget.setProperty("primary", primary)
    widget.clicked.connect(callback)
    return widget


def text_view(content=""):
    """Create a read-only, horizontally scrollable log/results view."""
    widget = QPlainTextEdit()
    widget.setReadOnly(True)
    widget.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    widget.setFont(QFont("Consolas" if sys.platform == "win32" else "Menlo", 10))
    widget.setPlainText(content)
    return widget


class CopyTable(QTableWidget):
    """Keep results read-only while exposing complete row and cell values for copying."""

    def keyPressEvent(self, event):
        """Copy selected rows using the platform's standard clipboard shortcut."""
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_selection()
            event.accept()
        else:
            super().keyPressEvent(event)

    def copy_selection(self):
        """Copy complete selected cells as tab-separated rows in displayed order."""
        indexes = sorted(self.selectedIndexes(), key=lambda index: (index.row(), index.column()))
        rows = {}
        for index in indexes:
            rows.setdefault(index.row(), []).append(str(index.data() or ""))
        if rows:
            QApplication.clipboard().setText("\n".join("\t".join(values) for values in rows.values()))

    def copy_value(self, value):
        """Copy a complete cell value even when the table visually shortens its path."""
        QApplication.clipboard().setText(value)

    def contextMenuEvent(self, event):
        """Offer copying the selection or just the cell under the pointer."""
        menu = QMenu(self)
        selection = menu.addAction("Copy selected rows", self.copy_selection)
        selection.setEnabled(bool(self.selectedIndexes()))
        item = self.itemAt(event.pos())
        value = menu.addAction("Copy value")
        value.setEnabled(item is not None)
        if item is not None:
            value.triggered.connect(partial(self.copy_value, item.text()))
        menu.exec(event.globalPos())

    def selection_snapshot(self):
        """Identify selected row contents so live refreshes do not change what gets copied."""
        selected = sorted({index.row() for index in self.selectedIndexes()})
        return [self.row_identity([self.item(row, column).text() if self.item(row, column) else ""
                                   for column in range(self.columnCount())]) for row in selected]

    def row_identity(self, values):
        """Follow paths and endpoints even when their counts or connection results change."""
        header = self.horizontalHeaderItem(0).text()
        if header == "Count":
            return tuple(values[1:])
        if header == "Endpoint":
            return tuple(values[:1])
        return tuple(values)

    def restore_selection(self, selected, rows):
        """Follow selected records as new live rows arrive, preserving duplicate selections."""
        self.clearSelection()
        available = {}
        for row, values in enumerate(rows):
            available.setdefault(self.row_identity(list(map(str, values))), []).append(row)
        for values in selected:
            matches = available.get(values, [])
            if matches:
                row = matches.pop(0)
                for column in range(self.columnCount()):
                    self.item(row, column).setSelected(True)


def table(headers):
    """Build an aligned read-only table with a stretchable final column."""
    widget = CopyTable(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    if headers[0] == "Count":
        widget.horizontalHeaderItem(0).setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    widget.verticalHeader().hide()
    widget.setAlternatingRowColors(True)
    widget.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
    widget.setToolTip("Ctrl+C copies selected rows. Right-click a cell to copy its complete value.")
    widget.setWordWrap(False)
    header = widget.horizontalHeader()
    for column in range(len(headers) - 1):
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        widget.setColumnWidth(column, 110 if column == 0 else 260)
    header.setSectionResizeMode(len(headers) - 1, QHeaderView.ResizeMode.Stretch)
    header.setMinimumSectionSize(80)
    return widget


def fill_table(widget, rows):
    """Replace rows while preserving scroll position and complete tooltip values."""
    scroll = widget.verticalScrollBar().value()
    selected = widget.selection_snapshot()
    widget.setUpdatesEnabled(False)
    widget.setRowCount(len(rows))
    for row, values in enumerate(rows):
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setToolTip(str(value))
            if column == 0 and widget.horizontalHeaderItem(0).text() == "Count":
                item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            widget.setItem(row, column, item)
    widget.setUpdatesEnabled(True)
    widget.restore_selection(selected, rows)
    widget.verticalScrollBar().setValue(scroll)


def save_text(parent, content):
    """Save the currently displayed result each time the user accepts the file dialog."""
    path, _ = QFileDialog.getSaveFileName(parent, "Save results", "analysis.log", "Log files (*.log);;Text files (*.txt)")
    if not path:
        return
    try:
        Path(path).write_text(content, encoding="utf-8")
    except OSError as error:
        QMessageBox.warning(parent, "Save error", str(error))


def fit_window(window, width=1000, height=720):
    """Keep initial windows within the available screen, including scaled desktops."""
    screen = window.screen() or QApplication.primaryScreen()
    available = screen.availableGeometry()
    window.resize(min(width, available.width() - 40), min(height, available.height() - 60))


class ResultDialog(QDialog):
    """Provide consistent margins, a resizable body, and a right-aligned close action."""

    def __init__(self, title, parent=None):
        """Initialize a dialog whose content grows with its window."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.closed = False
        self.finished.connect(self.dialog_finished)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 20, 20, 20)
        self.body.setSpacing(14)
        header = QHBoxLayout()
        header.addWidget(text_label(title, "section_heading"), 1)
        self.fullscreen_button = button("Full screen", self.toggle_full_screen)
        self.fullscreen_button.setToolTip("Toggle full screen (F11). Escape returns to the previous size.")
        header.addWidget(self.fullscreen_button)
        self.body.addLayout(header)
        self.fullscreen_shortcut = QShortcut(QKeySequence("F11"), self)
        self.fullscreen_shortcut.activated.connect(self.toggle_full_screen)
        self.footer = QHBoxLayout()
        self.footer.addStretch()
        self.footer.addWidget(button("Close", self.reject))
        fit_window(self)

    def toggle_full_screen(self):
        """Switch between full screen and the previous normal or maximized window state."""
        if self.isFullScreen():
            self.showNormal()
            if hasattr(self, "previous_geometry"):
                self.restoreGeometry(self.previous_geometry)
        else:
            self.previous_geometry = self.saveGeometry()
            self.showFullScreen()

    def changeEvent(self, event):
        """Keep the fullscreen action label synchronized with native window state changes."""
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange and hasattr(self, "fullscreen_button"):
            self.fullscreen_button.setText("Exit full screen" if self.isFullScreen() else "Full screen")

    def keyPressEvent(self, event):
        """Leave full screen on Escape before allowing a subsequent Escape to close the dialog."""
        if event.key() == Qt.Key.Key_Escape and self.isFullScreen():
            self.toggle_full_screen()
            event.accept()
        else:
            super().keyPressEvent(event)

    def finish_layout(self):
        """Put dialog actions after all content and align them along one baseline."""
        self.body.addLayout(self.footer)

    def dialog_finished(self, result):
        """Stop timer-driven collection when closing or rejecting a dialog."""
        self.closed = True
        if hasattr(self, "timer"):
            self.timer.stop()

    def closeEvent(self, event):
        """Cancel pending initial refreshes even when a dialog closes before its first paint."""
        self.dialog_finished(0)
        super().closeEvent(event)

    def retire(self, runner):
        """Release closed dialogs and their signal subscriptions after worker callbacks finish."""
        if runner.busy:
            runner.busy_changed.connect(self.dispose_when_idle)
        else:
            self.deleteLater()

    def dispose_when_idle(self, busy):
        """Keep a closed dialog alive only until its outstanding worker result is delivered."""
        if not busy:
            self.deleteLater()


class WorkSignals(QObject):
    """Deliver task outcomes to the Qt thread without manipulating worker-side widgets."""

    done = Signal(object)


class Work(QRunnable):
    """Execute one data operation outside the GUI event loop."""

    def __init__(self, operation, signals):
        """Retain the callable and signal bridge for a single bounded submission."""
        super().__init__()
        self.operation, self.signals = operation, signals

    def run(self):
        """Translate legacy startup exits and exceptions into visible UI failures."""
        try:
            outcome = (True, self.operation())
        except BaseException as error:
            logging.exception("Health Checker operation failed")
            outcome = (False, str(error) or "The operation failed. See amp_health_checker_log.log for details.")
        self.signals.done.emit(outcome)


class TaskRunner(QObject):
    """Serialize shared Data access and retain workers until their outcomes are delivered."""

    busy_changed = Signal(bool)

    def __init__(self, parent=None):
        """Create a single-worker queue, allowing at most one outstanding operation."""
        super().__init__(parent)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self.busy = False
        self.signals = WorkSignals(self)
        self.signals.done.connect(self.complete)
        self.callbacks = None

    def submit(self, operation, done, failed=None):
        """Run only when idle, preventing overlapping timers and duplicate button actions."""
        if self.busy:
            return False
        self.busy = True
        self.callbacks = (done, failed)
        self.busy_changed.emit(True)
        self.pool.start(Work(operation, self.signals))
        return True

    @Slot(object)
    def complete(self, outcome):
        """Deliver callbacks on the UI thread before announcing that data is idle."""
        done, failed = self.callbacks
        self.callbacks = None
        self.busy = False
        try:
            success, value = outcome
            if success:
                done(value)
            elif failed:
                failed(value)
        except Exception as error:
            logging.exception("Unable to display task results")
            QMessageBox.warning(None, "Display error", str(error))
        finally:
            self.busy_changed.emit(self.busy)
