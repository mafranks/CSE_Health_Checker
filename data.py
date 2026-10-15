"""Collect connector state, scan statistics, and authenticated policy metadata."""
import ast
import copy
import json
import logging
import os
import platform
import psutil
import re
import requests
import shutil
import socket
import struct
import subprocess
import time
import winreg
import xml.etree.ElementTree as ET
from collections import Counter
from dotenv import load_dotenv
from string import Template
from uuid import UUID
from sfc_log import SfcLogReader, parse_scan_event
from exclusions import read_policy_exclusions
from connector_logging import (
    ConnectorLogState, LOG_INFO, LOG_SOURCE_USER, logging_settings_from_root,
    read_logging_settings, resolve_logging_state,
)
from recommendations import recommend_exclusions

class PolicyLookupError(Exception):
    """Carry a policy API failure and its HTTP status for bounded fallback handling."""

    def __init__(self, message, status_code=None):
        """Store a readable error without treating a failed lookup as a version mismatch."""
        super().__init__(message)
        self.status_code = status_code


class Data:
    '''
    The data class is the instance containing most of the data for the health check.
    '''

    def __init__(self):
        """Initialize connector paths, collection state, and policy metadata."""
        logging.debug("Initializing Data...")
        self.check_for_amp()
        self.root_path = "C:/Program Files/Cisco/AMP"
        self.configure_connector_paths()
        self.log_reader = SfcLogReader()
        self.debug_error = ""
        self.enabled_debug = False
        self._debug_override = None
        self.reset_scan_data()
        self.converted_uptime = "Unknown"
        self.cpu_list = [(time.ctime(), self.get_cpu_usage())]
        self.current_cpu = self.cpu_list[-1][1]
        self.tetra_latest = 0
        self.api_cred_valid = False
        self.auth = False
        load_dotenv()
        self.load_dotenv_data()
        self.verify_api_creds()
        self.local_uuid = self.dig_thru_xml("agent", "uuid", root=self.get_root(os.path.join(self.root_path, "local.xml")), tag="")
        self.parse_xml(os.path.join(self.root_path, "policy.xml"))
        self._logging_policy = logging_settings_from_root(self.policy_xml_root)
        try:
            self.debug_check()
            self.finish_initialization()
        except BaseException:
            self.disable_debug()
            raise

    def finish_initialization(self):
        """Finish connector metadata initialization after configuring temporary logging."""
        self.local_uuid = self.dig_thru_xml("agent", "uuid", \
            root=self.get_root(os.path.join(self.root_path, "local.xml")), tag="")
        self.policy_color = 'Yellow'
        self.diag_failed = False

        if self.api_cred_valid:
            self.policy_serial_compare(self.policy_dict['policy_uuid'], \
                self.policy_dict['policy_sn'])
        self.refresh_local_tetra_version()
        self.isolation_check()
        logging.info('Data imports completed')

    def load_dotenv_data(self):
        """Load local API and deployment settings without exposing credential values."""
        logging.debug("Loading credentials from .env")
        self.client_id = os.getenv('CLIENT_ID')
        self.api_key = os.getenv('API_KEY')
        self.region = os.getenv('REGION')
        if self.region == "PC":
            self.pc_domain = os.getenv('PC_DOMAIN')
            self.pc_ca_path = os.getenv('PC_CA_PATH')
        self.set_region_urls()
        self.sx_client_id = os.getenv('SX_CLIENT_ID')
        self.sx_api_key = os.getenv('SX_API_KEY')
        self.org_name = os.getenv('ORG_NAME')
        self.auth = (self.client_id, self.api_key)
        self.proxies = os.getenv('PROXIES')
        if self.proxies:
            self.proxies = ast.literal_eval(self.proxies)

    def get_list_of_folders(self, file_path):
        """Return each parent folder of a Windows path for scan rankings."""

        list_of_folders = []
        split_it = file_path.split("\\")
        for i in range(1, len(split_it)):
            list_of_folders.append("\\".join(split_it[0:i+1]))
        return list_of_folders

    def __repr__(self):
        """Summarize collected engine activity without endpoint identifiers."""
        to_return = ""
        to_return += f"Cloud Lookup Count: {self.cloud_lookup_count}\n"
        to_return += f"TETRA Scan Count: {self.tetra_scan_count}\n"
        to_return += f"Excluded Count: {self.excluded_count}\n"
        to_return += f"Cache Hit Count: {self.cache_hit_count}\n"
        to_return += f"Malicious Hit Count: {self.malicious_hit_count}\n"
        to_return += f"Inner File Count: {self.inner_file_count}\n"

        return to_return

    def get_top_folders(self, n_count=None):
        """Rank folders while collapsing an adjacent parent with an identical child count."""
        counts = Counter(self.every_folder).most_common()
        filtered = []
        for index, (path, count) in enumerate(counts):
            if index + 1 < len(counts):
                next_path, next_count = counts[index + 1]
                if next_count == count and next_path.startswith(path.rstrip("\\") + "\\"):
                    continue
            filtered.append((path, count))
        return "\n".join(f"{count:<5} | {path}" for path, count in filtered[:n_count])

    def get_cpu_usage(self):
        """Read connector CPU usage, tolerating process exit and access denial."""
        cpu = 0.0
        processors = psutil.cpu_count() or 1
        for proc in psutil.process_iter():
            try:
                if proc.name().lower() == "sfc.exe":
                    cpu += proc.cpu_percent()
                    self.connector_started_at = proc.create_time()
                    uptime = int(time.time() - self.connector_started_at)
                    self.convert_uptime(uptime)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                logging.debug("Unable to sample process CPU: %s", error)
        return cpu / processors

    def get_version(self):
        """Find the latest valid installation only when the active path is unavailable."""
        root_path = getattr(self, "root_path", "C:/Program Files/Cisco/AMP")
        versions = []
        for entry in os.listdir(root_path):
            if re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", entry):
                if os.path.isfile(os.path.join(root_path, entry, "sfc.exe")):
                    versions.append(entry)
        if not versions:
            raise FileNotFoundError(f"No connector executable found under {root_path}")
        return max(versions, key=lambda version: tuple(map(int, version.split("."))))

    def get_connector_executable(self):
        """Find the running connector executable, excluding Windows System File Checker."""
        for proc in psutil.process_iter():
            try:
                if proc.name().lower() != "sfc.exe":
                    continue
                executable = proc.exe()
                version = os.path.basename(os.path.dirname(executable))
                if re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", version):
                    return executable
            except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                logging.debug("Unable to inspect connector executable: %s", error)
        return None

    def configure_connector_paths(self):
        """Use the running connector's directory for its logs and CLI commands."""
        executable = self.get_connector_executable()
        if executable:
            self.path_prelude = os.path.dirname(executable)
            self.root_path = os.path.dirname(self.path_prelude)
            self.version = os.path.basename(self.path_prelude)
        else:
            logging.warning("Active connector path unavailable; using latest installation")
            self.version = self.get_version()
            self.path_prelude = os.path.join(self.root_path, self.version)
        self.sfc_path = os.path.join(self.path_prelude, "sfc.exe.log")
        self.default_sfc_path = self.sfc_path
        logging.info("Selected connector log: %s", self.sfc_path)

    def convert_line(self, line):
        """Return a validated file/process record, or None for unsupported events."""
        return parse_scan_event(line)

    def reset_data(self):
        """Clear collected scan statistics and refresh main-page policy/isolation data."""
        self.reset_scan_data()
        if self.api_cred_valid:
            self.policy_serial_compare(self.policy_dict['policy_uuid'], self.policy_dict['policy_sn'])
        self.isolation_check()

    def reset_scan_data(self):
        """Clear all scan results without rewinding the live log or making API calls."""
        self.data = []
        self.every_folder = []
        self.ip_list = []
        self.excluded_list = []
        for field in (
            "spero_count", "ethos_count", "quarantine_count", "cloud_lookup_count",
            "tetra_scan_count", "excluded_count", "cache_hit_count",
            "malicious_hit_count", "inner_file_count",
        ):
            setattr(self, field, 0)

    def create_log_analysis(self, path):
        """Analyze a separate log snapshot without changing the live data or cursor."""
        analysis = copy.copy(self)
        analysis.sfc_path = os.fspath(path)
        analysis.log_reader = SfcLogReader()
        analysis.cpu_list = []
        analysis.debug_error = ""
        analysis.enabled_debug = False
        analysis._debug_override = None
        analysis.reset_scan_data()
        analysis.update(include_partial=True)
        return analysis

    def get_log_status(self):
        """Explain missing data instead of claiming successful collection unconditionally."""
        if self.log_reader.error:
            return "LOG READ ERROR", self.log_reader.error
        if not self.data and getattr(self, "debug_error", ""):
            return "DEBUG UNAVAILABLE", self.debug_error
        if self.log_reader.empty:
            return "EMPTY LOG", "The selected connector log is empty."
        if not self.data:
            return ("WAITING FOR SCAN EVENTS",
                    "No file/process scan events recognized. Check connector debug logging and generate file activity.")
        return "RUNNING", f"Collected {len(self.data)} file/process scan events."

    def update(self, include_partial=False):
        """Sample CPU and consume each newly completed connector log line once."""
        self.refresh_connector_logging()
        self.cpu_list.append((time.ctime(), self.get_cpu_usage()))
        self.current_cpu = self.cpu_list[-1][1]
        lines = self.log_reader.read_new_lines(self.sfc_path, include_partial=include_partial)
        for line in lines:
            self.process_log_line(line)
        logging.debug("Read %d new SFC lines; collected %d scan events", len(lines), len(self.data))

    def process_log_line(self, line):
        """Collect a valid scan event and count recognized connector operations."""
        if any(name in line for name in ("AMP_Health_Checker", "SE_Health_Checker", "main_page.py", "iptray.exe")):
            return
        if "Event::Handle" in line:
            record = self.convert_line(line)
            if record:
                self.data.append(record)
                self.every_folder.extend(self.get_list_of_folders(record["path"])[:-1])
            else:
                logging.debug("Unrecognized Event::Handle record skipped")
            if "EVENT_INNER_FILE_SCAN start" in line:
                self.inner_file_count += 1
        else:
            self.count_log_operation(line)
        if "disp 3" in line:
            self.malicious_hit_count += 1

    def count_log_operation(self, line):
        """Count known engine operations and safely extract exclusion/IP details."""
        markers = (
            ("GetSperoHash SPERO fingerprint: status: 1", "spero_count"),
            ("imn::CEventManager::PublishEvent: publishing type=553648143", "quarantine_count"),
            ("Query::LookupExecute: attempting lookup with cloud", "cloud_lookup_count"),
            ("ExclusionCheck: responding: is excluded", "excluded_count"),
            ("Cache::Get: age", "cache_hit_count"),
            ("calculating ETHOS hash", "ethos_count"),
        )
        for marker, field in markers:
            if marker in line:
                setattr(self, field, getattr(self, field) + 1)
                return
        if re.search(r"TetraEngineInterface::ScanFile\[\d+\] lock acquired", line):
            self.tetra_scan_count += 1
        elif "ExclusionCheck:" in line or "Exclusion::IsExcluded:" in line:
            self.count_exclusion(line)
        elif "NFMMemCache::Get: rip" in line:
            match = re.search(r"NFMMemCache::Get: rip: (\d+)", line)
            if match and 0 <= int(match[1]) <= 0xffffffff:
                address = socket.inet_ntoa(struct.pack('!L', int(match[1])))
                self.ip_list.append(".".join(reversed(address.split("."))))

    def count_exclusion(self, line):
        """Extract exclusions without indexing incomplete or differently spaced messages."""
        patterns = (r"ExclusionCheck:\s+(.+?) is excluded",
                    r"Exclusion::IsExcluded: result: 1 (?:from cache )?for (.+)")
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                self.excluded_list.append(match[1].split(",", 1)[0].strip())
                self.excluded_count += 1
                return

    def __len__(self):
        """Return the number of collected scan records."""
        return len(self.data)

    def get_top_exclusions(self, n_count=None):
        """Rank configured exclusions by their observed hit counts."""
        counts = Counter(self.excluded_list).most_common(n_count)
        return "\n".join(f"{count:<5} | {value.strip()}" for value, count in counts)

    def get_processes(self):
        '''
        Get list of processes.
        '''

        return list(map(lambda i: i["process"], self.data))

    def get_paths(self):
        '''
        Get list of paths.
        '''

        return list(map(lambda i: i["path"], self.data))

    def convert_to_layout(self, temp="$time || $process || $path\n"):
        '''
        Convert layout to proper format.
        '''

        template = Template(temp)
        b_w = [template.substitute(time=i["time"], process=i["process"], \
            path=i["path"]) for i in self.data]
        b_w.reverse()
        return "\n".join(b_w)

    def get_top_processes(self, n_count=None):
        """Rank processes by the number of collected scan events."""
        counts = Counter(self.get_processes()).most_common(n_count)
        return "\n".join(f"{count:<5} | {process}" for process, count in counts)

    def get_path_process_counts(self):
        """Rank unique process/file-path pairs across all collected scan events."""
        counts = Counter((record["process"], record["path"]) for record in self.data)
        return [(count, process, path) for (process, path), count in counts.most_common()]

    def export_path_process_counts(self):
        """Export every unique process/file-path pair with its complete scan count."""
        rows = self.get_path_process_counts()
        return "Count | Process | File path\n" + "\n".join(
            f"{count:<5} | {process} | {path}" for count, process, path in rows)

    def get_top_extensions(self, n_count=None):
        '''
        Get a list of the top extensions scanned by AMP.
        '''

        extensions = []
        for i in self.data:
            if "." in i["path"]:
                ext = i["path"].split(".")[-1]
                if len(ext) < 25:
                    extensions.append("." + ext)
                else:
                    extensions.append("." + ext[:25] + " (truncated)")
            else:
                extensions.append("[no period in file path]")
        c_count = Counter(extensions).most_common(n_count)
        return "\n".join([f"{i[1]:<5} | {i[0]}" for i in c_count])

    def get_top_paths(self, n_count=None):
        '''
        Get a list of the top paths scanned by AMP.
        '''

        c_count = Counter(self.get_paths()).most_common(n_count)
        return "\n".join([f"{i[1]:<5} | {i[0]}" for i in c_count])

    def dig_thru_xml(self, *args, root, tag="{http://www.w3.org/2000/09/xmldsig#}", is_list=False):
        """Read a bounded XML element path without logging configuration values."""
        if not args:
            raise ValueError("An XML element path is required")
        for name in args[:-1]:
            if root is None:
                return None
            root = root.find(f"{tag}{name}")
        if root is None:
            return None
        matches = root.findall(f"{tag}{args[-1]}")
        if not matches:
            return None
        return [element.text for element in matches] if is_list else matches[0].text

    def get_root(self, path):
        """Parse a local XML document without logging its contents."""
        return ET.parse(path).getroot()

    def parse_tetra_def_version(self, definitions):
        '''
        Extract the TETRA definition version from local.xml engine statistics.
        '''
        if not definitions:
            raise ValueError("TETRA definitions are missing")
        engine_definitions = json.loads(definitions).get('engineDefinitions', [])
        if not isinstance(engine_definitions, list):
            raise ValueError("TETRA engineDefinitions is not a list")

        for engine in engine_definitions:
            if not isinstance(engine, dict) or str(engine.get('engineId')) != "2":
                continue
            def_version = engine.get('defVersion', '')
            if not def_version:
                raise ValueError("TETRA defVersion is missing")
            return def_version.split(':')[-1].strip()
        raise ValueError("TETRA engine definition was not found")

    def refresh_local_tetra_version(self):
        '''
        Refresh the local TETRA version from local.xml.
        '''
        try:
            definitions = self.dig_thru_xml("agent", "engine", "stats", "definitions", \
                root=self.get_root(os.path.join(self.root_path, "local.xml")), tag="")
            self.tetra_version = self.parse_tetra_def_version(definitions)
            self.tetra_version_display = str(self.tetra_version)
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            logging.warning("Unable to determine TETRA version from local.xml")
            self.tetra_version = 0
            self.tetra_version_display = str(self.tetra_version)

    def refresh_local_policy_serial(self):
        """Refresh both the installed policy identifier and serial from local XML."""
        try:
            root = self.get_root(os.path.join(self.root_path, "policy.xml"))
            for field, tag in (("policy_uuid", "uuid"), ("policy_sn", "serial_number")):
                value = self.dig_thru_xml("Object", "config", "janus", "policy", tag, root=root)
                if value is not None and str(value).strip():
                    self.policy_dict[field] = value
        except (OSError, ET.ParseError) as error:
            logging.warning("Unable to refresh installed policy from policy.xml: %s", error)

    def parse_xml(self, path=r"C:/Program Files/Cisco/AMP/policy.xml"):
        """Read only policy fields needed by the dashboard and configured-exclusion viewer."""
        try:
            root = self.get_root(path)
        except OSError:
            if not self.api_cred_valid:
                raise RuntimeError("Unable to read policy; valid API credentials are required for cloud retrieval.")
            root = self.pull_private_policy() if self.region == "PC" else self.pull_policy_from_sx()
        self.policy_xml_root = root
        paths = {
            "policy_sn": ("janus", "policy", "serial_number"),
            "policy_uuid": ("janus", "policy", "uuid"),
            "tetra": ("agent", "scansettings", "tetra", "enable"),
            "spero": ("agent", "scansettings", "spero", "enable"),
            "ethos": ("agent", "scansettings", "ethos", "enable"),
            "spp": ("agent", "driver", "selfprotect", "spp"),
            "exprev_enable": ("agent", "exprev", "enable"),
            "DFC": ("agent", "nfm", "enable"),
            "orbital": ("orbital", "enablemsi"),
            "endpoint_isolation": ("agent", "endpointisolation", "enable"),
            "device_control": ("agent", "dc", "enabled"),
            "host_firewall": ("agent", "firewall", "mode"),
        }
        self.policy_dict = read_policy_exclusions(root)
        for key, parts in paths.items():
            self.policy_dict[key] = self.dig_thru_xml("Object", "config", *parts, root=root)

    def pull_private_policy(self):
        """Fetch Private Cloud policy XML with HTTP status and identifier validation."""
        computer = self.get_policy_api_data("computers", self.local_uuid)
        policy = computer.get("policy")
        if not isinstance(policy, dict):
            raise PolicyLookupError("Connector response has no policy assignment")
        guid = self.validate_policy_guid(policy.get("guid"))
        options = {"auth": self.auth, "verify": self.pc_ca_path, "timeout": 15}
        if self.proxies:
            options["proxies"] = self.proxies
        response = requests.get(f"{self.base_secure_endpoint_url}/v1/policies/{guid}.xml", **options)
        if response.status_code != 200:
            raise PolicyLookupError(f"Unable to retrieve policy XML (HTTP {response.status_code})", response.status_code)
        return ET.fromstring(response.content)

    def isolation_check(self):
        """Query the isolation value directly, avoiding registry enumeration end errors."""
        self.isolated = 'Not Isolated'
        self.unlock_code = ''
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Immunet Protect", 0,
                                winreg.KEY_WOW64_64KEY | winreg.KEY_READ) as key:
                try:
                    unlock_code, _ = winreg.QueryValueEx(key, "unlock_code")
                except FileNotFoundError:
                    logging.debug("No isolation unlock code is present")
                    return
        except OSError as error:
            logging.warning("Unable to read connector isolation status: %s", error)
            self.isolated = 'Unknown'
            return
        if unlock_code:
            self.isolated = 'Isolated'
            self.isolation_code(self.local_uuid)

    def isolation_code(self, local_uuid):
        '''
        Pull the isolation code if the endpoint is isolated.
        '''
        logging.debug(f"Checking isolation for {local_uuid}")
        self.unlock_code = ''
        if self.region == 'NAM':
            url = f"https://api.amp.cisco.com/v1/computers/{local_uuid}/isolation"
        elif self.region == 'EU':
            url = f"https://api.eu.amp.cisco.com/v1/computers/{local_uuid}/isolation"
        elif self.region == 'APJC':
            url = f"https://api.apjc.amp.cisco.com/v1/computers/{local_uuid}/isolation"
        elif self.region == 'PC':
            url = f"https://console.{self.pc_domain}/v1/computers/{local_uuid}/isolation"
        try:
            if self.region == "PC":
                if self.proxies:
                    r = requests.get(url, auth=self.auth, verify=self.pc_ca_path, proxies=self.proxies, timeout=15)
                else:
                    r = requests.get(url, auth=self.auth, verify=self.pc_ca_path, timeout=15)
            else:
                if self.proxies:
                    r = requests.get(url, auth=self.auth, proxies=self.proxies, timeout=15)
                else:
                    r = requests.get(url, auth=self.auth, timeout=15)
            j = json.loads(r.content)
            self.unlock_code = f"Unlock Code: {j['data']['unlock_code']}"
        except requests.exceptions.ConnectionError:
            logging.warning("requests.exceptions.ConnectionError")
            self.unlock_code = ''
        except KeyError:
            logging.warning("KeyError")
            self.unlock_code = ''

    def policy_serial_compare(self, policy_uuid, policy_xml_serial):
        """Compare verified serials and distinguish lookup failures from outdated policies."""
        self.policy_serial = None
        self.policy_color = 'Yellow'
        self.policy_error = ""
        self.policy_notice = ""
        try:
            policy = self.get_latest_policy(policy_uuid)
            serial = policy.get('serial_number', policy.get('serialNumber'))
            self.policy_serial = self.validate_policy_serial(serial)
            installed_serial = self.validate_policy_serial(policy_xml_serial)
            if not self.policy_notice:
                self.policy_color = 'Green' if self.policy_serial == installed_serial else 'Red'
            logging.info("Policy check: installed serial %s, cloud serial %s, status %s",
                         installed_serial, self.policy_serial, self.policy_color)
            return True
        except requests.exceptions.RequestException as error:
            self.policy_error = "Policy API connection failed; check connectivity and proxy settings."
            logging.warning("Policy version check failed: %s", error)
            return False
        except (PolicyLookupError, ValueError, TypeError) as error:
            self.policy_error = str(error) or "Unable to retrieve the latest policy"
            logging.warning("Policy version check failed: %s", self.policy_error)
            return False

    def get_latest_policy(self, policy_uuid):
        """Retry a missing local policy using the connector's current cloud assignment."""
        self.latest_policy_uuid = self.validate_policy_guid(policy_uuid)
        try:
            return self.get_policy_api_data("policies", self.latest_policy_uuid)
        except PolicyLookupError as error:
            if error.status_code != 404:
                raise
            computer = self.get_policy_api_data("computers", self.local_uuid)
            assignment = computer.get("policy")
            if not isinstance(assignment, dict) or not assignment.get("guid"):
                raise PolicyLookupError("Connector response has no assigned policy") from error
            assigned_guid = self.validate_policy_guid(assignment["guid"])
            if assigned_guid == self.latest_policy_uuid:
                raise
            logging.warning("Local policy lookup returned 404; retrying cloud-assigned policy %s", assigned_guid)
            self.latest_policy_uuid = assigned_guid
            policy = self.get_policy_api_data("policies", assigned_guid)
            self.policy_notice = "Local/cloud policy identifiers differ; check policy assignment."
            return policy

    def get_policy_api_data(self, resource, guid):
        """Make a bounded HTTPS API request and reject HTTP errors or invalid envelopes."""
        if resource not in ("policies", "computers"):
            raise ValueError("Unsupported policy lookup resource")
        if self.region not in ("NAM", "EU", "APJC", "PC"):
            raise ValueError("Unknown API region; check REGION in .env")
        guid = self.validate_policy_guid(guid)
        self.set_region_urls()
        url = f"{self.base_secure_endpoint_url}/v1/{resource}/{guid}"
        options = {"auth": self.auth, "timeout": 10}
        if self.proxies:
            options["proxies"] = self.proxies
        if self.region == "PC":
            if not self.pc_ca_path:
                raise ValueError("Private Cloud CA path is missing")
            options["verify"] = self.pc_ca_path
        logging.debug("Policy API request: %s", url)
        response = requests.get(url, **options)
        if response.status_code != 200:
            label = "Policy" if resource == "policies" else "Connector"
            descriptions = {401: "API authentication failed", 403: "API access denied",
                            404: f"{label} not found; check API organization and region",
                            429: "API rate limit reached"}
            message = descriptions.get(response.status_code, "API request failed")
            raise PolicyLookupError(f"{message} (HTTP {response.status_code})", response.status_code)
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict) or payload.get("errors"):
            raise PolicyLookupError("Invalid policy API response")
        return payload["data"]

    @staticmethod
    def validate_policy_guid(value):
        """Normalize valid identifiers and give a readable error for missing or invalid values."""
        try:
            return str(UUID(str(value)))
        except ValueError as error:
            raise PolicyLookupError("Policy or connector identifier is missing or invalid") from error

    @staticmethod
    def validate_policy_serial(value):
        """Require a nonnegative integer serial before comparing policy versions."""
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("Policy serial is missing or invalid")
        serial = int(value)
        if serial < 0:
            raise ValueError("Policy serial cannot be negative")
        return serial

    def get_policy_check_text(self):
        """Format either a verified latest serial or the reason the check could not complete."""
        detail = self.policy_error or self.policy_notice
        if self.policy_serial is None:
            return detail or "Latest policy unavailable"
        text = f"Latest Serial: {self.policy_serial}"
        return f"{text}\n{detail}" if detail else text

    def tetra_def_compare(self):
        '''
        Check to see if the TETRA definitions are up to date.
        '''
        self.tetra_latest, self.tetra_error = 0, ""
        self.refresh_local_tetra_version()
        if platform.machine().endswith('64'):
            url = "http://update.amp.cisco.com/av64bit/versions.id"
        else:
            url = "http://update.amp.cisco.com/av32bit/versions.id"
        logging.debug(f"requesting {url}")
        try:
            if self.proxies:
                r = requests.get(url, proxies=self.proxies, timeout=10)
            else:
                r = requests.get(url, timeout=10)
            r.raise_for_status()
            j = r.text
            self.tetra_latest = j.split('value="')[1].split('"')[0]
            logging.debug(f"tetra_latest: {self.tetra_latest}")
            logging.debug(f"data.tetra_version: {self.tetra_version}")
            if (int(self.tetra_latest) - int(self.tetra_version)) <= 5:
                self.tetra_color = "green"
                self.tetra_version_display = str(self.tetra_version)
            elif self.tetra_version == 0 and self.policy_dict['tetra'] == "1":
                self.tetra_color = "yellow"
                self.tetra_version_display = str(self.tetra_version)
            elif self.tetra_version == 0 and self.policy_dict['tetra'] == "0":
                self.tetra_color = "red"
                self.tetra_version_display = "DISABLED"
            else:
                self.tetra_color = "yellow"
                self.tetra_version_display = str(self.tetra_version)
        except requests.exceptions.RequestException as e:
            logging.warning(f"Unable to retrieve latest TETRA version: {e}")
            self.tetra_color = "yellow"
            self.tetra_error = "Latest TETRA version unavailable. Check network connectivity and retry."
        except (IndexError, TypeError, ValueError):
            logging.warning("Unable to parse latest TETRA version")
            self.tetra_color = "yellow"
            self.tetra_error = "Latest TETRA version unavailable. The update server returned an invalid version."

    def update_api_calls(self):
        '''
        Update the information pulled via the API.
        '''
        logging.info("Running update_api_calls")
        self.refresh_local_policy_serial()
        self.policy_serial_compare(self.policy_dict['policy_uuid'], self.policy_dict['policy_sn'])
        self.tetra_def_compare()

    def verify_api_creds(self):
        """Check optional API credentials without logging them or sending empty credentials."""
        self.api_cred_valid = False
        if not self.client_id or not self.api_key:
            return
        self.set_region_urls()
        options = {"auth": self.auth, "timeout": 15}
        if self.proxies:
            options["proxies"] = self.proxies
        if self.region == "PC":
            if not self.pc_ca_path:
                raise ValueError("Private Cloud CA path is missing")
            options["verify"] = self.pc_ca_path
        try:
            response = requests.get(f"{self.base_secure_endpoint_url}/v1/version", **options)
            self.api_cred_valid = response.status_code == 200
            logging.debug("API credential verification returned HTTP %s", response.status_code)
        except requests.exceptions.RequestException:
            logging.warning("API credential verification failed due to a network error")

    def check_for_amp(self):
        """Verify that a connector process is running while tolerating inaccessible processes."""
        for proc in psutil.process_iter():
            try:
                if proc.name().lower() == "sfc.exe" and proc.is_running():
                    return
            except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                logging.debug("Unable to inspect process: %s", error)
        raise RuntimeError("Ensure Secure Endpoint is installed and running and try again.")

    def recommend_exclusions(self):
        """Match running software to public exclusion-set candidates without changing policy."""
        processes = []
        for process in psutil.process_iter():
            try:
                processes.append(process.name())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return recommend_exclusions(processes, proxies=self.proxies)

    def debug_check(self):
        """Enable temporary debug only when policy and saved settings establish it is off."""
        if self.enabled_debug:
            return
        self.debug_error = ""
        self._debug_override = None
        state = self.refresh_connector_logging(force=True)
        if state.enabled:
            logging.info("Existing connector debug logging is preserved (%s)", state.source)
            return
        if not state.may_enable:
            self.debug_error = state.detail
            logging.warning("Connector logging settings are preserved: %s", state.detail)
            return
        started_at = int(time.time())
        if not self.run_debug_command("start"):
            return
        completed_at = int(time.time())
        self.confirm_debug_override(started_at, completed_at)

    def read_connector_logging(self):
        """Combine current local settings, readable policy XML, and connector defaults."""
        policy = dict(getattr(self, "_logging_policy", {}))
        policy.setdefault("level", self.policy_dict.get("log_level"))
        try:
            local = read_logging_settings(os.path.join(self.root_path, "local.xml"))
            defaults = self.optional_logging_settings("global.xml")
            current_policy = self.optional_logging_settings("policy.xml")
            policy.update({key: value for key, value in current_policy.items() if value is not None})
            return resolve_logging_state(policy, local, defaults, time.time(),
                                         started_at=getattr(self, "connector_started_at", None))
        except (OSError, ET.ParseError) as error:
            logging.debug("Unable to inspect connector logging configuration: %s", error)
            return ConnectorLogState(None, "unknown", "Unable to read connector logging settings; check file access and the connector's debug control.")

    def optional_logging_settings(self, filename):
        """Read a policy/default file when present, keeping other read failures visible."""
        if filename not in ("global.xml", "policy.xml"):
            raise ValueError("Unsupported connector logging configuration file")
        try:
            return read_logging_settings(os.path.join(self.root_path, filename))
        except FileNotFoundError:
            return {}
        except PermissionError:
            if filename == "policy.xml":
                return {}
            raise

    def refresh_connector_logging(self, force=False):
        """Refresh inferred connector state at most once every five seconds during polling."""
        now = time.monotonic()
        state = getattr(self, "connector_logging", None)
        if force or state is None or now - getattr(self, "_logging_checked_at", 0) >= 5:
            self.connector_logging = self.read_connector_logging()
            self._logging_checked_at = now
            if self.connector_logging.enabled:
                self.debug_error = ""
        return self.connector_logging

    def confirm_debug_override(self, started_at, completed_at):
        """Claim cleanup ownership only for a fresh local override created during this command."""
        for attempt in range(3):
            state = self.refresh_connector_logging(force=True)
            token = state.override
            if token and token[:2] == (LOG_INFO, LOG_SOURCE_USER) and started_at <= token[2] <= completed_at:
                self._debug_override = token
                self.enabled_debug = True
                logging.info("Health Checker temporary connector debug override verified")
                return
            if attempt < 2:
                time.sleep(0.1)
        self.debug_error = "The debug command completed, but its setting could not be verified; check the connector's debug control."
        logging.warning(self.debug_error)

    def get_connector_debug_text(self):
        """Describe connector logging separately from the Health Checker's own log level."""
        state = self.refresh_connector_logging()
        label = "Unknown" if state.enabled is None else "Enabled" if state.enabled else "Disabled"
        source = state.source
        if self.enabled_debug and state.override == self._debug_override:
            source = "Health Checker"
        return f"{label} ({source})"

    def run_debug_command(self, action):
        """Verify the connector CLI succeeds before reporting a debug logging change."""
        if action not in ("start", "stop"):
            raise ValueError(f"Invalid debug logging action: {action}")
        executable = os.path.join(self.path_prelude, "sfc.exe")
        try:
            subprocess.run([executable, '-l', action], check=True, timeout=15,
                           capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as error:
            self.debug_error = (f"Unable to {action} connector debug logging: {error}. "
                                "Run the Health Checker as Administrator and check connector logging.")
            logging.warning(self.debug_error)
            return False
        self.debug_error = ""
        logging.info("Connector debug logging %s command completed successfully", action)
        return True

    def disable_debug(self):
        """Clear only the verified override this tool created, preserving later external changes."""
        if not self.enabled_debug:
            return
        state = self.refresh_connector_logging(force=True)
        if state.override != self._debug_override or self._debug_override is None:
            logging.info("Connector logging changed or could not be verified; current settings are preserved")
            self.enabled_debug = False
            self._debug_override = None
            return
        if self.run_debug_command("stop"):
            self.enabled_debug = False
            self._debug_override = None
            self.refresh_connector_logging(force=True)

    def convert_uptime(self, uptime, granularity=4):
        '''
        Convert the pulled uptime into a readable format.
        '''
        intervals = (
            ('weeks', 604800),
            ('days', 86400),
            ('hours', 3600),
            ('mins', 60),
            ('secs', 1),
        )

        result = []
        for name, count in intervals:
            value = uptime // count
            if value:
                uptime -= value * count
                if value == 1:
                    name = name.rstrip('s')
                result.append(f"{value} {name}")
        self.converted_uptime = ', '.join(result[:granularity])

    def get_top_ips(self, ip_list, n=10):
        '''
        Get a list of the top IPs seen by AMP.
        '''
        c = Counter(ip_list)
        to_return = []
        for i in c.most_common(n):
            to_return.append(f"{i[1]:5}: {i[0]:<}")
        return "\n".join(to_return)

    def generate_diagnostic(self):
        """Launch the connector diagnostic and copy the local Health Checker log."""
        self.diag_failed = False
        src = os.path.join(os.getcwd(), 'amp_health_checker_log.log')
        dst = os.path.join(os.environ['HOMEPATH'], 'Desktop')
        try:
            shutil.copy(src, dst)
        except FileNotFoundError:
            logging.error(f"FileNotFoundError: Source: {src} | Dest: {dst}")
            self.diag_failed = True

        try:
            subprocess.Popen([os.path.join(self.path_prelude, "ipsupporttool.exe")])
            logging.info("Support Diagnostic Tool started.")
        except OSError as e:
            logging.error(e)
            self.diag_failed = True

    def pull_policy_from_sx(self):
        """Retrieve public-cloud policy XML using the documented authenticated API."""
        if not self.org_name:
            raise RuntimeError("Set ORG_NAME in .env to retrieve policy XML from the cloud.")
        computer = self.get_policy_api_data("computers", self.local_uuid)
        assignment = computer.get("policy")
        if not isinstance(assignment, dict):
            raise PolicyLookupError("Connector response has no policy assignment")
        guid = self.validate_policy_guid(assignment.get("guid"))
        options = {"headers": {"Authorization": f"Bearer {self.get_se_access_token()}"}, "timeout": 15}
        if self.proxies:
            options["proxies"] = self.proxies
        response = requests.get(f"{self.base_secure_endpoint_url}/v3/organizations?size=100", **options)
        if response.status_code != 200:
            raise PolicyLookupError(f"Organization lookup failed (HTTP {response.status_code})", response.status_code)
        payload = response.json()
        organizations = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(organizations, list):
            raise PolicyLookupError("Invalid organization API response")
        matches = [org.get("organizationIdentifier") for org in organizations
                   if isinstance(org, dict) and org.get("name") == self.org_name]
        if len(matches) != 1 or not isinstance(matches[0], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", matches[0]):
            raise PolicyLookupError("Organization name must match exactly one accessible organization")
        url = f"{self.base_secure_endpoint_url}/v3/organizations/{matches[0]}/policies/{guid}/xml"
        response = requests.get(url, **options)
        if response.status_code != 200:
            raise PolicyLookupError(f"Policy XML lookup failed (HTTP {response.status_code})", response.status_code)
        return ET.fromstring(response.content)

    def set_region_urls(self):
        """Set documented regional API hosts and reject unsupported deployment settings."""
        if self.region == "NAM":
            self.base_securex_url = "https://visibility.amp.cisco.com"
            self.base_secure_endpoint_url = "https://api.amp.cisco.com"
        elif self.region == "EU":
            self.base_securex_url = "https://visibility.eu.amp.cisco.com"
            self.base_secure_endpoint_url = "https://api.eu.amp.cisco.com"
        elif self.region == "APJC":
            self.base_securex_url = "https://visibility.apjc.amp.cisco.com"
            self.base_secure_endpoint_url = "https://api.apjc.amp.cisco.com"
        elif self.region == "PC":
            self.base_secure_endpoint_url = f"https://console.{self.pc_domain}"
        else:
            raise ValueError("Unknown API region; check REGION in .env")

    def get_se_access_token(self):
        """Exchange local XDR credentials for an Endpoint token without logging secrets."""
        if not self.sx_client_id or not self.sx_api_key:
            raise RuntimeError("Set SX_CLIENT_ID and SX_API_KEY in .env for cloud policy retrieval.")
        options = {"timeout": 15}
        if self.proxies:
            options["proxies"] = self.proxies
        response = requests.post(
            f"{self.base_securex_url}/iroh/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data={"grant_type": "client_credentials"}, auth=(self.sx_client_id, self.sx_api_key), **options)
        token = self.response_access_token(response)
        response = requests.post(f"{self.base_secure_endpoint_url}/v3/access_tokens",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"},
                                 data={"grant_type": "client_credentials"}, **options)
        return self.response_access_token(response)

    @staticmethod
    def response_access_token(response):
        """Reject HTTP failures and malformed authentication responses without exposing their bodies."""
        if not 200 <= response.status_code < 300:
            raise RuntimeError(f"API authentication failed (HTTP {response.status_code})")
        payload = response.json()
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError("API authentication returned no access token")
        return token
