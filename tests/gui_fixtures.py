"""Offline connector data used by Qt tests and layout previews."""

from pathlib import Path
from unittest.mock import Mock

from test_health_checker import Data
from test_sfc_log import scan_event
from sfc_log import SfcLogReader
from recommendations import RecommendationReport


def populate_test_dashboard_metadata(data):
    """Assign synthetic values for tests/screenshots only; production never calls this helper."""
    data.current_cpu = 0.4
    data.version = "8.6.4.30695"
    data.converted_uptime = "4 days, 3 hours, 43 minutes"
    data.isolated, data.unlock_code = "Not Isolated", ""
    data.local_uuid = "00000000-0000-4000-8000-000000000001"
    data.tetra_version_display, data.tetra_latest = "97526", "97526"
    data.tetra_color, data.policy_color = "Green", "Yellow"
    data.tetra_def_compare = Mock()
    data.recommend_exclusions = Mock(return_value=RecommendationReport(
        {"Example product": ("example.exe",)}, "https://github.com/CiscoSecurity/amp-05-health-checker-windows",
        "2024-10-30", "Not refreshed", "Synthetic recommendation example for layout tests."))
    data.policy_dict["policy_sn"] = "4147"
    data.api_cred_valid = True
    return data


def sample_data(directory):
    """Create a real collector with local fixture XML/logs and no connector/API operations."""
    root = Path(directory)
    (root / "local.xml").write_text("<config><agent><log/></agent></config>")
    path = root / "sfc.exe.log"
    path.write_text(scan_event() * 12 + "NFMMemCache::Get: rip: 16843009\n")
    data = Data.__new__(Data)
    data.root_path = data.path_prelude = str(root)
    data.sfc_path = data.default_sfc_path = str(path)
    data.region = "NAM"
    data.proxies = None
    data.cpu_list = []
    data.get_cpu_usage = Mock(return_value=0.4)
    data.policy_dict = {"log_level": "1", "tetra": "1", "spero": "1", "ethos": "1", "orbital": "0", "DFC": "1", "spp": "1",
                        "exprev_enable": "1", "endpoint_isolation": "1", "device_control": "0", "host_firewall": "disabled",
                        "path_exclusions": ["256|3|0|0|.example", r"256|2|1|0|C:\Example\Cache",
                                            r"256|6|0|0|^C:\\Example\\.*\\cache"],
                        "process_exclusions": [r"2|0||C:\Example\worker.exe|1|", r"3|0||C:\Example\service.exe|4|",
                                               r"3|0||C:\Example\sample.exe|48|", r"3|0||C:\Example\monitor.exe|256|"],
                        "executable_exclusions": [("example.exe", "v8")]}
    data.enabled_debug, data.debug_error, data._debug_override = False, "", None
    data.log_reader = SfcLogReader()
    data.reset_scan_data()
    populate_test_dashboard_metadata(data)
    data.policy_error = ""
    data.policy_notice = ""
    data.policy_serial = 4147
    data.policy_color = "Green"
    data.update()
    return data
