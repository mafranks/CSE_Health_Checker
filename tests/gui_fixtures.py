"""Offline connector data used by Qt tests and layout previews."""

from pathlib import Path
from unittest.mock import Mock

from test_health_checker import Data
from test_sfc_log import scan_event
from sfc_log import SfcLogReader


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
    data.policy_dict = {"tetra": "1", "spero": "1", "ethos": "1", "orbital": "0", "DFC": "1", "spp": "1",
                        "exprev_enable": "1", "endpoint_isolation": "1", "device_control": "0", "host_firewall": "disabled",
                        "path_exclusions": ["Example policy entry for local review"],
                        "process_exclusions": [r"3|0||C:\Example\sample.exe|48|"]}
    data.log_reader = SfcLogReader()
    data.reset_scan_data()
    populate_test_dashboard_metadata(data)
    data.policy_error = ""
    data.policy_notice = ""
    data.policy_serial = 4147
    data.policy_color = "Green"
    data.update()
    return data
