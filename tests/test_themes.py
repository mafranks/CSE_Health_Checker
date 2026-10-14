"""Validate real theme settings, system appearance changes, and readable color pairs."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QColor, QPalette

from qt_helpers import APP
from themes import COLORS, ThemeManager, theme_palette


def contrast_ratio(foreground, background):
    """Measure WCAG contrast for the text/background pairs actually used by the themes."""
    luminances = []
    for color in (QColor(foreground), QColor(background)):
        channels = (color.redF(), color.greenF(), color.blueF())
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
        luminances.append(sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722))))
    return (max(luminances) + 0.05) / (min(luminances) + 0.05)


class ThemeTests(unittest.TestCase):
    """Exercise appearance logic without changing the user's real system or stored preference."""

    def setUp(self):
        """Isolate settings and platform signals while keeping the real application palette."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "appearance.ini")
        self.settings = QSettings(self.path, QSettings.Format.IniFormat)
        self.hints = Mock()
        self.hints.colorScheme.return_value = Qt.ColorScheme.Dark
        hints_patch = patch.object(APP, "styleHints", return_value=self.hints)
        hints_patch.start()
        self.addCleanup(hints_patch.stop)
        self.addCleanup(APP.theme.refresh)

    def test_first_launch_follows_dark_system_and_live_changes(self):
        """Start dark, follow a light system notification, and avoid saving an implicit choice."""
        manager = ThemeManager(APP, self.settings)
        self.assertEqual(manager.current, "dark")
        self.assertIsNone(manager.preference)
        self.assertFalse(self.settings.contains("theme"))
        manager.system_changed(Qt.ColorScheme.Light)
        APP.processEvents()
        self.assertEqual(manager.current, "light")
        self.assertFalse(self.settings.contains("theme"))

    def test_saved_choice_survives_restart_and_overrides_system(self):
        """Restore both explicit choices from disk even when the system reports the opposite."""
        for choice in COLORS:
            with self.subTest(choice=choice):
                manager = ThemeManager(APP, self.settings)
                manager.select(choice)
                restored = ThemeManager(APP, QSettings(self.path, QSettings.Format.IniFormat))
                self.assertEqual(restored.current, choice)
                opposite = Qt.ColorScheme.Light if choice == "dark" else Qt.ColorScheme.Dark
                restored.system_changed(opposite)
                APP.processEvents()
                self.assertEqual(restored.current, choice)
                self.assertEqual(APP.palette().window().color().name(), COLORS[choice]["window"])

    def test_invalid_saved_preference_falls_back_to_system(self):
        """Ignore malformed settings and reject invalid explicit choices before changing appearance."""
        self.settings.setValue("theme", "unsupported")
        manager = ThemeManager(APP, self.settings)
        self.assertIsNone(manager.preference)
        self.assertEqual(manager.current, "dark")
        with self.assertRaises(ValueError):
            manager.select("unsupported")
        self.assertEqual(manager.current, "dark")

    def test_unknown_system_scheme_uses_original_palette(self):
        """Use the platform's original window brightness when appearance detection is unavailable."""
        self.hints.colorScheme.return_value = Qt.ColorScheme.Unknown
        for choice in COLORS:
            APP.setPalette(theme_palette(choice))
            manager = ThemeManager(APP, self.settings)
            self.assertEqual(manager.current, choice)

    def test_active_inactive_and_disabled_palette_colors_are_readable(self):
        """Maintain readable widget text when windows lose focus or controls are disabled."""
        for choice in COLORS:
            palette = theme_palette(choice)
            for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive, QPalette.ColorGroup.Disabled):
                for text, background in ((QPalette.ColorRole.WindowText, QPalette.ColorRole.Window),
                                         (QPalette.ColorRole.Text, QPalette.ColorRole.Base),
                                         (QPalette.ColorRole.ButtonText, QPalette.ColorRole.Button),
                                         (QPalette.ColorRole.HighlightedText, QPalette.ColorRole.Highlight)):
                    with self.subTest(choice=choice, group=group, text=text):
                        ratio = contrast_ratio(palette.color(group, text).name(), palette.color(group, background).name())
                        self.assertGreaterEqual(ratio, 4.5)

    def test_theme_text_and_status_colors_have_sufficient_contrast(self):
        """Keep normal, muted, selected, and semantic status text readable in either mode."""
        for choice, colors in COLORS.items():
            pairs = [("text", background) for background in ("window", "surface", "header", "alternate", "selection", "hover")]
            pairs += [("muted", background) for background in ("window", "surface", "status")]
            pairs += [("primary_text", background) for background in ("primary", "primary_hover")]
            pairs += [(f"{tone}_text", f"{tone}_bg") for tone in ("good", "warning", "bad", "neutral")]
            for foreground, background in pairs:
                with self.subTest(choice=choice, foreground=foreground, background=background):
                    self.assertGreaterEqual(contrast_ratio(colors[foreground], colors[background]), 4.5)
