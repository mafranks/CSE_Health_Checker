"""Render illustrative Qt screenshots using local fixture data and no live services."""

import argparse
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from PySide6.QtTest import QTest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qt_helpers import APP, wait_until
from gui_fixtures import sample_data
from main_page import MainWindow
from certificates import read_certificate_file
from connectivity import endpoints_for_region
import popups


DISPLAY_PATH = r"C:\Program Files\Cisco\AMP\8.6.4.30695\sfc.exe.log"


def capture(widget, path, width=1000, height=720):
    """Render settled layout geometry before exporting an actual Qt widget image."""
    widget.resize(width, height)
    widget.show()
    widget.activateWindow()
    for _ in range(5):
        APP.processEvents()
    QTest.qWait(30)
    widget.grab().save(str(path))


def capture_details(window, output):
    """Replace legacy detail images with current Qt cards and illustrative values."""
    window.data.isolated, window.data.unlock_code = "Isolated", "Unlock Code: 12345678"
    window.update_status()
    APP.processEvents()
    window.fields["unlock"].parentWidget().grab().save(str(output / "Isolation_Code.png"))
    window.fields["tetra"].parentWidget().grab().save(str(output / "TETRA_Version.png"))
    window.data.isolated, window.data.unlock_code = "Not Isolated", ""
    window.update_status()


def capture_tools(window, data, output):
    """Render each tool with synthetic endpoint data and public reference certificates."""
    constructors = (
        ("Live_Debugging.png", lambda: popups.LiveScanDialog(data, window.runner, window)),
        ("Live_Top_Processes.png", lambda: popups.LiveScanDialog(data, window.runner, window, processes=True)),
        ("Run_Analysis.png", lambda: popups.AnalysisDialog(data, window.runner, window)),
        ("Manual_Analysis.png", lambda: popups.ManualAnalysisDialog(data, window.runner, window)),
        ("Check_Engines.png", lambda: popups.EnginesDialog(data, window)),
        ("Certificate_Viewer.png", lambda: popups.CertificatesDialog(window, certificates=read_certificate_file(
            Path(__file__).parent / "fixtures" / "example_certificate.pem"))),
        ("Trusted_Signers.png", lambda: popups.TrustedSignersDialog(window)),
        ("Recommend_Exclusions.png", lambda: popups.RecommendationsDialog(data, window.runner, window)),
        ("View_Exclusions.png", lambda: popups.ExclusionsDialog(data, window)),
    )
    for name, create in constructors:
        dialog = create()
        dialog.show()
        APP.processEvents()
        wait_until(lambda: not window.runner.busy)
        if hasattr(dialog, "timer"):
            dialog.timer.stop()
        if isinstance(dialog, popups.LogDialog):
            dialog.source.setText(DISPLAY_PATH)
        if name == "Live_Debugging.png":
            dialog.running, dialog.started = True, True
            popups.set_badge(dialog.status, "RUNNING", "good")
            dialog.detail.setText(f"Collected {len(data.data)} file/process scan events.")
            dialog.set_busy(False)
        capture(dialog, output / name)
        if isinstance(dialog, popups.ExclusionsDialog):
            dialog.tabs.setCurrentIndex(1)
            capture(dialog, output / "View_Process_Exclusions.png")
        dialog.close()


def render(output, theme="light"):
    """Export the dashboard and every major tool with a deterministic theme and fixture data."""
    APP.theme.select(theme)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        data = sample_data(directory)
        window = MainWindow(data_factory=lambda: data)
        window.show()
        wait_until(lambda: window.data is not None and not window.runner.busy)
        window.timer.stop()
        capture(window, output / "Main_Page.png", 1120, 760)
        capture_details(window, output)
        capture_tools(window, data, output)
        results = {url: "Green" for url in endpoints_for_region("NAM")}
        with patch.object(popups, "check_endpoints", return_value=results):
            connectivity = popups.ConnectivityDialog(data, window.runner, window)
            connectivity.show()
            APP.processEvents()
            wait_until(lambda: not window.runner.busy)
            capture(connectivity, output / "Connectivity.png")
            connectivity.close()
        window.close()
        wait_until(lambda: window.can_close and not window.runner.busy)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/tmp/cse-qt-previews"))
    parser.add_argument("--theme", choices=("light", "dark"), default="light")
    args = parser.parse_args()
    render(args.output, args.theme)
