"""Complete Qt light/dark themes and a saved, application-wide appearance choice."""

import logging
from string import Template

from PySide6.QtCore import QObject, QSettings, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QPalette


COLORS = {
    "light": {
        "window": "#f3f6fa", "surface": "#ffffff", "text": "#172b45", "muted": "#52657b",
        "border": "#cbd7e5", "hover": "#eaf3fc", "selection": "#dceeff",
        "accent": "#1977b8", "link": "#086da9", "primary": "#086da9", "primary_hover": "#085b8c",
        "primary_text": "#ffffff", "disabled": "#edf1f5", "disabled_text": "#596a80",
        "header": "#edf3fa", "alternate": "#f8fafd", "status": "#e9eff7",
        "good_bg": "#e4f5eb", "good_text": "#155e38",
        "warning_bg": "#fff1d0", "warning_text": "#755000",
        "bad_bg": "#fde7e7", "bad_text": "#a22020",
        "neutral_bg": "#e9eff7", "neutral_text": "#304e72",
        "tooltip_bg": "#172b45", "tooltip_text": "#ffffff",
    },
    "dark": {
        "window": "#151e2b", "surface": "#202c3d", "text": "#edf3fc", "muted": "#b1c0d4",
        "border": "#45576e", "hover": "#2b3e55", "selection": "#284e73",
        "accent": "#76baff", "link": "#8bc8ff", "primary": "#19689e", "primary_hover": "#217bb6",
        "primary_text": "#ffffff", "disabled": "#253143", "disabled_text": "#8b9ab0",
        "header": "#29384c", "alternate": "#253246", "status": "#1c293a",
        "good_bg": "#163e30", "good_text": "#9ce1b4",
        "warning_bg": "#4a3919", "warning_text": "#ffe29a",
        "bad_bg": "#4c252b", "bad_text": "#ffb6bb",
        "neutral_bg": "#283b52", "neutral_text": "#c8dfff",
        "tooltip_bg": "#edf3fc", "tooltip_text": "#151e2b",
    },
}

STYLE = Template("""
QWidget { color: $text; font-size: 10pt; }
QMainWindow, QDialog, QWidget#dashboard { background: $window; }
QGroupBox { background: $surface; border: 1px solid $border; border-radius: 10px;
    margin-top: 12px; padding: 18px 14px 14px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 16px; padding: 0 5px;
    color: $text; background: $window; }
QLabel { background: transparent; font-weight: normal; }
QLabel[role="heading"] { font-size: 22pt; font-weight: 700; }
QLabel[role="section_heading"] { font-size: 14pt; font-weight: 600; }
QLabel[role="muted"] { color: $muted; }
QLabel[role="badge"] { border-radius: 5px; padding: 5px 9px; font-weight: 600; }
QLabel[tone="good"] { background: $good_bg; color: $good_text; }
QLabel[tone="warning"] { background: $warning_bg; color: $warning_text; }
QLabel[tone="bad"] { background: $bad_bg; color: $bad_text; }
QLabel[tone="neutral"] { background: $neutral_bg; color: $neutral_text; }
QPushButton { background: $surface; border: 1px solid $border; border-radius: 6px;
    padding: 9px 14px; min-height: 20px; font-weight: 500; }
QPushButton:hover { background: $hover; border-color: $accent; }
QPushButton:pressed, QPushButton:checked { background: $selection; border-color: $accent; }
QPushButton[primary="true"] { background: $primary; border-color: $primary; color: $primary_text; }
QPushButton[primary="true"]:hover, QPushButton[primary="true"]:pressed { background: $primary_hover; }
QPushButton:disabled, QPushButton[primary="true"]:disabled {
    background: $disabled; color: $disabled_text; border-color: $border; }
QPushButton:focus { border: 2px solid $accent; }
QComboBox, QLineEdit { background: $surface; border: 1px solid $border; border-radius: 6px;
    padding: 9px 10px; min-height: 20px; selection-background-color: $selection; selection-color: $text; }
QComboBox { min-width: 75px; }
QComboBox:focus, QLineEdit:focus { border-color: $accent; }
QComboBox:disabled, QLineEdit:disabled { background: $disabled; color: $disabled_text; }
QAbstractItemView, QPlainTextEdit { background: $surface; border: 1px solid $border;
    border-radius: 6px; selection-background-color: $selection; selection-color: $text; }
QHeaderView::section { background: $header; color: $text; border: none;
    border-bottom: 1px solid $border; padding: 8px; font-weight: 600; }
QTableWidget { gridline-color: $border; alternate-background-color: $alternate; }
QTabWidget::pane { border: 1px solid $border; background: $surface; border-radius: 6px; }
QTabBar::tab { background: $window; padding: 10px 15px; margin-right: 3px; color: $muted; }
QTabBar::tab:selected { background: $surface; color: $link; border-bottom: 3px solid $accent; }
QTabBar::tab:hover { background: $hover; }
QScrollArea { border: none; background: transparent; }
QStatusBar { background: $status; color: $muted; padding: 3px; }
QProgressBar { background: $disabled; border: 1px solid $border; border-radius: 4px; }
QProgressBar::chunk { background: $accent; border-radius: 3px; }
QMenu { background: $surface; color: $text; border: 1px solid $border; padding: 4px; }
QMenu::item { padding: 6px 20px; }
QMenu::item:selected { background: $selection; color: $text; }
QMenu::item:disabled { color: $disabled_text; }
QToolTip { background: $tooltip_bg; color: $tooltip_text; border: none; padding: 6px; }
""")


def theme_palette(name):
    """Set every relevant palette role so unstyled Qt controls match the chosen theme."""
    if name not in COLORS:
        raise ValueError("Theme must be light or dark")
    colors = COLORS[name]
    palette = QPalette()
    roles = {
        "Window": "window", "WindowText": "text", "Base": "surface", "AlternateBase": "alternate",
        "Text": "text", "Button": "surface", "ButtonText": "text", "BrightText": "primary_text",
        "Highlight": "selection", "HighlightedText": "text", "Accent": "accent",
        "ToolTipBase": "tooltip_bg", "ToolTipText": "tooltip_text",
        "Link": "link", "LinkVisited": "link", "PlaceholderText": "disabled_text",
        "Light": "hover", "Midlight": "header", "Mid": "border", "Dark": "border", "Shadow": "window",
    }
    for role, key in roles.items():
        palette.setColor(getattr(QPalette.ColorRole, role), QColor(colors[key]))
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(colors["disabled_text"]))
    for role in (QPalette.ColorRole.Base, QPalette.ColorRole.Button):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(colors["disabled"]))
    return palette


def system_theme(app):
    """Read the system appearance before replacing Qt's palette, with a palette fallback."""
    scheme = app.styleHints().colorScheme()
    if scheme == Qt.ColorScheme.Unknown:
        return "dark" if app.palette().window().color().lightness() < 128 else "light"
    return "dark" if scheme == Qt.ColorScheme.Dark else "light"


class ThemeManager(QObject):
    """Follow system appearance until the user chooses and saves light or dark mode."""

    changed = Signal(str)

    def __init__(self, app, settings=None):
        """Restore a validated preference and subscribe once to system appearance changes."""
        super().__init__(app)
        self.app = app
        self.settings = settings if settings is not None else QSettings("Secure Endpoint Health Checker", "Appearance")
        saved = self.settings.value("theme")
        self.preference = saved if saved in ("light", "dark") else None
        self.system = system_theme(app)
        if self.preference:
            app.styleHints().setColorScheme(Qt.ColorScheme.Dark if self.preference == "dark" else Qt.ColorScheme.Light)
        self.apply(self.preference or self.system)
        app.styleHints().colorSchemeChanged.connect(self.system_changed)

    def apply(self, name):
        """Update existing and future windows together without changing their data or geometry."""
        palette = theme_palette(name)
        self.current = name
        self.app.setPalette(palette)
        self.app.setStyleSheet(STYLE.substitute(COLORS[name]))
        self.changed.emit(name)

    def select(self, name):
        """Apply an explicit choice immediately and persist it across application restarts."""
        if name not in COLORS:
            raise ValueError("Theme must be light or dark")
        self.preference = name
        self.app.styleHints().setColorScheme(Qt.ColorScheme.Dark if name == "dark" else Qt.ColorScheme.Light)
        self.apply(name)
        self.settings.setValue("theme", name)
        self.settings.sync()
        if self.settings.status() != QSettings.Status.NoError:
            logging.warning("Unable to save the appearance preference")

    def system_changed(self, scheme):
        """Reapply after Qt updates its platform palette, preserving any explicit choice."""
        if scheme != Qt.ColorScheme.Unknown:
            self.system = "dark" if scheme == Qt.ColorScheme.Dark else "light"
        QTimer.singleShot(0, self.refresh)

    def refresh(self):
        """Resolve the latest preference after a queued system appearance notification."""
        self.apply(self.preference or self.system)
