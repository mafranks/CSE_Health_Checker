"""Verify that reading scan data and selecting a tool log level leave connector settings unchanged."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gui_fixtures import sample_data
from test_health_checker import Data, data_module, main_page


class ConnectorDebugTests(unittest.TestCase):
    """Keep connector runtime verification manual and tool logging independent."""

    def test_runtime_debug_requires_manual_verification(self):
        """Avoid interpreting the connector's runtime state from unverified local settings."""
        self.assertEqual(Data.get_connector_debug_text(), 'Unknown (check connector GUI)')

    def test_collection_never_changes_connector_configuration(self):
        """Keep local configuration bytes intact and never invoke a connector debug command."""
        with tempfile.TemporaryDirectory() as directory:
            data = sample_data(directory)
            path = Path(directory) / 'local.xml'
            original = path.read_bytes()
            with patch.object(data_module.subprocess, 'run') as run:
                data.update()
                data.get_connector_debug_text()
            self.assertEqual(path.read_bytes(), original)
            run.assert_not_called()

    def test_tool_log_selection_does_not_issue_connector_commands(self):
        """Keep Python INFO/WARNING/DEBUG selection independent of connector logging."""
        logger = main_page.logging.getLogger()
        original = logger.level
        try:
            with patch.object(data_module.subprocess, 'run') as run:
                for name in ('INFO', 'WARNING', 'DEBUG'):
                    main_page.set_tool_log_level(name)
                    self.assertEqual(logger.level, getattr(main_page.logging, name))
            run.assert_not_called()
        finally:
            logger.setLevel(original)
