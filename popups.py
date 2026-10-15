"""Resizable Qt dialogs for live collection, analysis, and connector diagnostics."""

from functools import partial
import re
import threading
import webbrowser

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QComboBox, QFileDialog, QGridLayout, QGroupBox, QHBoxLayout, QLineEdit, QSizePolicy, QTabWidget, QVBoxLayout, QWidget

from certificates import certificate_reports, load_certificates
from exclusions import EXCLUSION_TYPES, PROCESS_TYPES, configured_exclusions
from connectivity import ConnectivitySettings, REGIONS, check_endpoints, endpoints_for_region, environment_settings, parse_proxy
from gui import ResultDialog, button, fill_table, save_text, set_badge, table, text_label, text_view


SCAN_COUNTERS = (
    ("Cloud lookups", "cloud_lookup_count"), ("Excluded", "excluded_count"),
    ("Cache hits", "cache_hit_count"), ("TETRA scans", "tetra_scan_count"),
    ("SPERO scans", "spero_count"), ("ETHOS scans", "ethos_count"),
    ("Malicious", "malicious_hit_count"), ("Quarantined", "quarantine_count"),
    ("Inner file scans", "inner_file_count"),
)
SECTION_TITLES = ("Processes", "Paths", "Extensions", "Folders", "Exclusions hit", "IPs")


def analysis_sections(data):
    """Keep all six analysis categories available for display and text export."""
    return {
        "_top_processes": "Top 10 Processes\n" + data.get_top_processes(10),
        "_top_paths": "Top 10 Paths\n" + data.get_top_paths(10),
        "_top_extensions": "Top 10 Extensions\n" + data.get_top_extensions(10),
        "_top_folders": "Top 10 Folders\n" + data.get_top_folders(10),
        "_top_exclusions": "Top 10 Exclusions Hit\n" + data.get_top_exclusions(10),
        "_top_ips": "Top 10 IPs\n" + data.get_top_ips(data.ip_list),
    }


def ranking_rows(content):
    """Split count/value result lines while preserving delimiters inside path values."""
    rows = []
    for line in content.splitlines():
        match = re.match(r"\s*(\d+)\s*(?:\||:)\s*(.*)", line)
        if match:
            rows.append(match.groups())
    return rows


def check_policy(data):
    """Refresh and compare policy metadata without touching GUI objects."""
    if not data.api_cred_valid:
        data.policy_color = "Yellow"
        data.policy_error = "Invalid API credentials"
        return
    data.refresh_local_policy_serial()
    data.policy_serial_compare(data.policy_dict.get("policy_uuid"), data.policy_dict.get("policy_sn"))


class LogDialog(ResultDialog):
    """Share source, status, counters, and safe background refresh across log windows."""

    def __init__(self, title, data, runner, parent=None):
        """Build an aligned source panel and retain the shared, serialized task runner."""
        super().__init__(title, parent)
        self.data, self.runner = data, runner
        self.source = text_label(data.sfc_path)
        self.source.setToolTip(data.sfc_path)
        self.status, self.detail = text_label(), text_label(role="muted")
        self.status.setWordWrap(False)
        grid = QGridLayout()
        grid.setColumnMinimumWidth(0, 95)
        grid.setColumnStretch(1, 1)
        grid.addWidget(text_label("Source log", "muted"), 0, 0)
        grid.addWidget(self.source, 0, 1)
        status_row = QHBoxLayout()
        status_row.addWidget(self.status)
        status_row.addWidget(self.detail, 1)
        grid.addLayout(status_row, 1, 0, 1, 2)
        group = QGroupBox("Collection status")
        group.setLayout(grid)
        self.body.addWidget(group)
        self.counters = {}
        self.show_status()

    def show_status(self, snapshot=False):
        """Display collection health, distinguishing complete snapshots from live streams."""
        status, detail = self.data.get_log_status()
        if snapshot and status == "RUNNING":
            status = "ANALYSIS COMPLETE"
        tone = "good" if status in ("RUNNING", "ANALYSIS COMPLETE") else "warning"
        if status == "LOG READ ERROR":
            tone = "bad"
        set_badge(self.status, status, tone)
        self.detail.setText(detail)
        self.source.setText(self.data.sfc_path)
        self.source.setToolTip(self.data.sfc_path)

    def add_counters(self):
        """Use a three-column grid so every counter name and value has the same alignment."""
        group = QGroupBox("Scan activity")
        grid = QGridLayout(group)
        grid.setHorizontalSpacing(24)
        for index, (title, field) in enumerate(SCAN_COUNTERS):
            row, column = divmod(index, 3)
            value = text_label("0")
            grid.addWidget(text_label(title, "muted"), row, column * 2)
            grid.addWidget(value, row, column * 2 + 1)
            grid.setColumnStretch(column * 2, 1)
            self.counters[field] = value
        self.body.addWidget(group)
        self.counter_group = group

    def update_counters(self):
        """Render counter values only after the corresponding worker operation completes."""
        for field, label in self.counters.items():
            label.setText(str(getattr(self.data, field, 0)))

    def failure(self, message):
        """Keep refresh errors visible in the dialog while preserving previously collected data."""
        if not self.closed:
            set_badge(self.status, "CHECK FAILED", "bad")
            self.detail.setText(message)


class AnalysisDialog(LogDialog):
    """Show all analysis categories in resizable tabs with a complete export."""

    def __init__(self, data, runner, parent=None, manual=False):
        """Create six aligned ranking tables rather than stacking oversized text boxes."""
        super().__init__("Manual SFC Analysis" if manual else "Run Analysis", data, runner, parent)
        self.manual = manual
        self.tabs = QTabWidget()
        self.tables = {}
        for key, title in zip(analysis_sections(data), SECTION_TITLES):
            view = table(("Count", title))
            self.tables[key] = view
            self.tabs.addTab(view, title)
        self.body.addWidget(self.tabs, 1)
        self.empty_note = text_label("", "muted")
        self.body.addWidget(self.empty_note)
        self.refresh_button = button("Analyze" if manual else "Refresh results", self.refresh_data)
        self.save_button = button("Save results…", self.save_results)
        self.footer.insertWidget(0, self.refresh_button)
        self.footer.insertWidget(1, self.save_button)
        self.finish_layout()
        self.runner.busy_changed.connect(self.set_busy)
        self.set_busy(self.runner.busy)
        self.render_results()
        if not manual:
            self.timer = QTimer(self)
            self.timer.setInterval(3000)
            self.timer.timeout.connect(self.refresh_data)
            self.timer.start()

    def set_busy(self, busy):
        """Disable snapshot/export actions while their shared data is being modified."""
        self.refresh_button.setEnabled(not busy)
        self.save_button.setEnabled(not busy)

    def refresh_data(self):
        """Collect the next live batch through the same queue used by the main window."""
        if not self.closed:
            self.runner.submit(self.data.update, self.render_results, self.failure)

    def render_results(self, result=None):
        """Update every category and provide useful guidance for an empty analysis."""
        if self.closed:
            return
        for key, content in analysis_sections(self.data).items():
            fill_table(self.tables[key], ranking_rows(content))
        self.update_counters()
        self.show_status(snapshot=self.manual)
        self.empty_note.setText("No scan records collected. The collection status above explains why." if not self.data.data else "")

    def save_results(self):
        """Export every analysis tab, including IPs, using a fresh native file dialog."""
        save_text(self, "\n\n".join(analysis_sections(self.data).values()))


class ManualAnalysisDialog(AnalysisDialog):
    """Analyze selected files independently from the live collector."""

    def __init__(self, data, runner, parent=None):
        """Add native file selection and separate snapshot state to the analysis view."""
        super().__init__(data, runner, parent, manual=True)
        self.source_data = data
        self.selected_path = data.default_sfc_path
        actions = QHBoxLayout()
        self.choose_button = button("Choose SFC log…", self.choose_file)
        self.reset_button = button("Use connector log", self.reset_file)
        actions.addWidget(self.choose_button)
        actions.addWidget(self.reset_button)
        actions.addStretch()
        self.body.insertLayout(2, actions)
        self.add_counters()
        self.body.removeWidget(self.counter_group)
        self.body.insertWidget(3, self.counter_group)
        self.select_path(self.selected_path)
        QTimer.singleShot(0, self.refresh_data)

    def set_busy(self, busy):
        """Keep file selection and snapshot controls consistent during background analysis."""
        super().set_busy(busy)
        if hasattr(self, "choose_button"):
            self.choose_button.setEnabled(not busy)
            self.reset_button.setEnabled(not busy)
        if hasattr(self, "selected_path") and self.selected_path != self.data.sfc_path:
            self.save_button.setEnabled(False)

    def select_path(self, path):
        """Clear old results when the selected source changes to avoid mislabelled exports."""
        self.selected_path = path
        self.source.setText(path)
        self.source.setToolTip(path)
        for view in self.tables.values():
            fill_table(view, [])
        for label in self.counters.values():
            label.setText("0")
        set_badge(self.status, "READY")
        self.detail.setText("Press Analyze to read the selected log.")
        self.empty_note.setText("")
        self.save_button.setEnabled(False)

    def choose_file(self):
        """Select a local log using the platform's file picker without changing live data."""
        path, _ = QFileDialog.getOpenFileName(self, "Choose SFC log", self.selected_path, "Log files (*.log);;All files (*)")
        if path:
            self.select_path(path)

    def reset_file(self):
        """Return the selected source to the connector's current log."""
        self.select_path(self.source_data.default_sfc_path)

    def refresh_data(self):
        """Create a fresh snapshot in the background without redirecting the live log reader."""
        if not self.closed:
            self.runner.submit(partial(self.source_data.create_log_analysis, self.selected_path), self.accept_snapshot, self.failure)

    def accept_snapshot(self, snapshot):
        """Display completed snapshot results and enable exporting that exact source."""
        self.data = snapshot
        self.render_results()
        self.save_button.setEnabled(True)


class LiveScanDialog(LogDialog):
    """Rank collected scans by process or process/file-path pair, with full exports."""

    def __init__(self, data, runner, parent=None, processes=False):
        """Create aligned controls, counters, and a large scrolling ranking table."""
        super().__init__("Live Top Processes" if processes else "Live Path and Process", data, runner, parent)
        self.processes, self.running, self.started = processes, processes, processes
        self.add_counters()
        self.cpu = text_label("", "muted")
        self.body.addWidget(self.cpu)
        self.results = table(("Count", "Process") if processes else ("Count", "Process", "File path"))
        self.body.addWidget(self.results, 1)
        self.limit_note = text_label("", "muted")
        self.body.addWidget(self.limit_note)
        self.start_button = button("Start / Resume", self.start, primary=True)
        self.pause_button = button("Pause", self.pause)
        self.reset_button = button("Reset data", self.reset)
        self.save_button = button("Save results…", self.save_results)
        for index, control in enumerate((self.start_button, self.pause_button, self.reset_button, self.save_button)):
            self.footer.insertWidget(index, control)
        self.finish_layout()
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.collect)
        self.timer.start()
        self.runner.busy_changed.connect(self.set_busy)
        self.render_results()
        self.set_busy(self.runner.busy)
        if not self.running:
            set_badge(self.status, "READY")
            self.detail.setText("Press Start / Resume to collect scan events.")

    def set_busy(self, busy):
        """Align enabled actions with collection state and the shared background queue."""
        self.start_button.setEnabled(not busy and not self.running)
        self.pause_button.setEnabled(self.running)
        self.reset_button.setEnabled(not busy)
        self.save_button.setEnabled(not busy)

    def start(self):
        """Begin a new session once, then resume without discarding collected results."""
        if not self.started:
            self.data.reset_scan_data()
            self.started = True
        self.running = True
        self.set_busy(self.runner.busy)
        self.collect()

    def pause(self):
        """Stop future polling while retaining the last completed collection batch."""
        self.running = False
        set_badge(self.status, "PAUSED")
        self.detail.setText("Collection paused. Resume to read new scan events.")
        self.set_busy(self.runner.busy)

    def reset(self):
        """Reset counters without rewinding the live log or invoking cloud APIs."""
        self.data.reset_scan_data()
        self.running, self.started = False, False
        self.render_results()
        set_badge(self.status, "READY")
        self.detail.setText("Press Start / Resume to collect scan events.")
        self.set_busy(self.runner.busy)

    def collect(self):
        """Schedule at most one scan read at a time while this dialog is active."""
        if self.running and not self.closed:
            self.runner.submit(self.data.update, self.render_results, self.failure)

    def render_results(self, result=None):
        """Render bounded rankings using counts from the complete collection session."""
        if self.closed:
            return
        if self.processes:
            rows = ranking_rows(self.data.get_top_processes(100))
            note = "Showing the top 100 processes. Export includes all collected process rankings."
        else:
            rankings = self.data.get_path_process_counts()
            rows = rankings[:500]
            note = (f"Showing {len(rows)} of {len(rankings)} unique process/path pairs "
                    f"from {len(self.data.data)} scan events. Export includes all pairs and counts.")
        fill_table(self.results, rows)
        self.limit_note.setText(note)
        self.cpu.setText(f"Connector CPU: {self.data.current_cpu:.2f}%")
        self.update_counters()
        self.show_status()
        if not self.running and self.started:
            self.pause()

    def save_results(self):
        """Save every ranking with counts, including pairs beyond the table preview."""
        content = self.data.get_top_processes() if self.processes else self.data.export_path_process_counts()
        save_text(self, content)


class ConnectivityDialog(ResultDialog):
    """Run regional connectivity tests independently of connector installation and API credentials."""

    endpoint_result = Signal(str, str)

    def __init__(self, data, runner, parent=None):
        """Offer network settings and results even when connector initialization is unavailable."""
        super().__init__("Connectivity test", parent)
        self.runner = runner
        self.cancelled = threading.Event()
        self.settings_error = ""
        try:
            self.settings = (ConnectivitySettings(data.region, getattr(data, "pc_domain", ""), getattr(data, "proxies", None))
                             if data is not None else environment_settings())
        except (OSError, ValueError) as error:
            self.settings = ConnectivitySettings()
            self.settings_error = str(error)
        self.add_network_controls()
        self.status = text_label()
        set_badge(self.status, "READY")
        self.results = table(("Endpoint", "Result"))
        self.results.setColumnWidth(0, 500)
        self.body.addWidget(self.status)
        self.body.addWidget(self.results, 1)
        self.test_button = button("Test again", self.run_test, primary=True)
        self.footer.insertWidget(0, self.test_button)
        self.finish_layout()
        self.runner.busy_changed.connect(self.set_busy)
        self.endpoint_result.connect(self.show_endpoint_result)
        self.current_endpoints = []
        self.set_busy(self.runner.busy)
        QTimer.singleShot(0, self.run_test)

    def add_network_controls(self):
        """Make cloud region and Private Cloud domain explicit without requiring a .env file."""
        self.body.addWidget(text_label("Choose the cloud region to test. No connector or API credentials are required.", "muted"))
        controls = QHBoxLayout()
        region_label = text_label("Region", "muted", wrap=False)
        region_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        controls.addWidget(region_label)
        self.region = QComboBox()
        self.region.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        self.region.addItems(REGIONS)
        if self.settings.region not in REGIONS:
            self.settings_error = "Invalid REGION in .env. Choose NAM, EU, APJC, or PC."
            self.region.insertItem(0, "Choose region")
            self.region.setCurrentIndex(0)
        else:
            self.region.setCurrentText(self.settings.region)
        controls.addWidget(self.region)
        self.domain_label = text_label("Private Cloud domain", "muted", wrap=False)
        self.domain_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        self.domain_input = QLineEdit(self.settings.domain)
        self.domain_input.setPlaceholderText("example.local")
        controls.addWidget(self.domain_label)
        controls.addWidget(self.domain_input, 1)
        controls.addStretch()
        self.body.addLayout(controls)
        self.region.currentTextChanged.connect(self.region_changed)
        self.region_changed()

    def region_changed(self, region=None):
        """Show the domain input only for Private Cloud and let users fix a missing region."""
        private = self.region.currentText() == "PC"
        self.domain_label.setVisible(private)
        self.domain_input.setVisible(private)
        if self.region.currentText() in REGIONS and self.settings_error.startswith("Invalid REGION"):
            self.settings_error = ""

    def dialog_finished(self, result):
        """Avoid launching an initial test or rendering results after the window closes."""
        self.cancelled.set()
        super().dialog_finished(result)

    def set_busy(self, busy):
        """Prevent a second connectivity test from overlapping the first."""
        self.test_button.setEnabled(not busy)
        self.region.setEnabled(not busy)
        self.domain_input.setEnabled(not busy)

    def run_test(self):
        """Start a serialized connectivity operation and label the in-progress result."""
        if self.closed:
            return
        if self.runner.busy:
            return
        try:
            if self.settings_error:
                raise ValueError(self.settings_error)
            endpoints = endpoints_for_region(self.region.currentText(), self.domain_input.text())
            parse_proxy(self.settings.proxies)
        except ValueError as error:
            self.failure(str(error))
            return
        self.current_endpoints = endpoints
        fill_table(self.results, [(url, "Checking…") for url in endpoints])
        operation = partial(check_endpoints, endpoints, proxies=self.settings.proxies,
                            cancelled=self.cancelled.is_set, on_result=self.endpoint_result.emit)
        if self.runner.submit(operation, self.render_results, self.failure):
            set_badge(self.status, "CHECKING ENDPOINTS")

    def show_endpoint_result(self, endpoint, color):
        """Display progress on the GUI thread as each bounded network check finishes."""
        if not self.closed and endpoint in self.current_endpoints:
            row = self.current_endpoints.index(endpoint)
            self.results.item(row, 1).setText("Connected" if color == "Green" else "Connection failed")

    def render_results(self, results):
        """Show explicit pass/fail text so results do not rely on color alone."""
        if self.closed:
            return
        fill_table(self.results, [(url, "Connected" if color == "Green" else "Connection failed") for url, color in results.items()])
        failed = sum(color != "Green" for color in results.values())
        set_badge(self.status, f"COMPLETE · {failed} failed", "warning" if failed else "good")

    def failure(self, message):
        """Explain a failed connectivity operation in the same window."""
        if not self.closed:
            set_badge(self.status, message, "bad")


class TextDialog(ResultDialog):
    """Display read-only diagnostic information with a consistent close/export footer."""

    def __init__(self, title, description, content, parent=None):
        """Build a scrollable report that fits long paths and smaller displays."""
        super().__init__(title, parent)
        self.body.addWidget(text_label(description, "muted"))
        self.results = text_view(content)
        self.body.addWidget(self.results, 1)
        self.footer.insertWidget(0, button("Save results…", self.save_results))
        self.finish_layout()

    def save_results(self):
        """Export exactly the read-only report currently displayed."""
        save_text(self, self.results.toPlainText())


class CertificatesDialog(ResultDialog):
    """Display only user-selected certificates in separate validity-date tabs."""

    def __init__(self, parent=None, certificates=(), as_of=None):
        """Create an empty local viewer with bounded certificate selection and complete exports."""
        super().__init__("Certificate viewer", parent)
        self.as_of = as_of
        self.body.addWidget(text_label(
            "Open certificate-only PEM, CER, CRT, or DER files to view fingerprints and dates. "
            "These date categories do not establish current trust.", "muted"))
        self.notice = text_label("No certificates loaded.", "muted")
        self.body.addWidget(self.notice)
        self.tabs = QTabWidget()
        self.views = {}
        self.body.addWidget(self.tabs, 1)
        self.open_button = button("Open certificates…", self.choose_files)
        self.save_button = button("Save all tabs…", self.save_results)
        self.footer.insertWidget(0, self.open_button)
        self.footer.insertWidget(1, self.save_button)
        self.render_certificates(certificates)
        self.finish_layout()

    def render_certificates(self, certificates):
        """Replace all categories together after a complete successful file selection."""
        reports = certificate_reports(certificates, self.as_of)
        for view in self.views.values():
            view.deleteLater()
        self.tabs.clear()
        self.views = {}
        self.reports = reports
        for title, (count, content) in reports.items():
            view = text_view(content)
            self.views[title] = view
            self.tabs.addTab(view, f"{title} ({count})")
        count = len(certificates)
        self.notice.setText(f"Loaded {count} certificate variant" + ("." if count == 1 else "s.") if count else "No certificates loaded.")
        self.save_button.setEnabled(bool(certificates))

    def choose_files(self):
        """Read selected public certificate files locally and retain results if selection fails."""
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Open certificates", "", "Certificates (*.pem *.cer *.crt *.der);;All files (*)")
        if not paths:
            return
        try:
            certificates = load_certificates(paths)
        except (OSError, ValueError) as error:
            self.notice.setText(str(error))
            return
        self.render_certificates(certificates)

    def save_results(self):
        """Export every date category with the same classification timestamp."""
        save_text(self, "\n\n".join(content for _, content in self.reports.values()))


class EnginesDialog(ResultDialog):
    """Show engine configuration as read-only status rows instead of editable checkboxes."""

    def __init__(self, data, parent=None):
        """Align engine names and explicit enabled/disabled/unknown values."""
        super().__init__("Engine status", parent)
        fields = (("SHA", None), ("TETRA", "tetra"), ("Exploit Prevention", "exprev_enable"),
                  ("Network Monitoring", "DFC"), ("System Process Protection", "spp"),
                  ("ETHOS", "ethos"), ("SPERO", "spero"), ("Orbital", "orbital"),
                  ("Endpoint Isolation", "endpoint_isolation"), ("Device Control", "device_control"),
                  ("Host Firewall", "host_firewall"))
        rows = []
        for name, key in fields:
            value = "1" if key is None else data.policy_dict.get(key)
            status = "Unknown" if value is None else "Enabled" if str(value).lower() in ("1", "enabled") else "Disabled"
            rows.append((name, status))
        self.results = table(("Engine", "Policy setting"))
        self.results.setColumnWidth(0, 330)
        fill_table(self.results, rows)
        self.body.addWidget(self.results, 1)
        self.finish_layout()


class ExclusionsDialog(ResultDialog):
    """Show typed exclusions and per-engine process scope with filters and full exports."""

    def __init__(self, data, parent=None):
        """Decode the loaded policy into separate file and process exclusion tables."""
        super().__init__("Policy exclusions", parent)
        general, processes = configured_exclusions(data.policy_dict)
        self.records = {"general": general, "process": processes}
        self.tabs = QTabWidget()
        self.views, self.filters, self.messages = {}, {}, {}
        self.add_exclusions_tab("Exclusions", "general", EXCLUSION_TYPES)
        self.add_exclusions_tab("Process exclusions", "process", PROCESS_TYPES)
        self.body.addWidget(self.tabs, 1)
        self.body.addWidget(text_label("Configured rules from the loaded policy; runtime enforcement is not checked.", "muted"))
        self.save_button = button("Save all tabs…", self.save_results)
        self.footer.insertWidget(0, self.save_button)
        self.finish_layout()

    def add_exclusions_tab(self, title, key, types):
        """Give each read-only exclusion table its own type selector and result count."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        controls = QHBoxLayout()
        controls.addWidget(text_label("Type", "muted", wrap=False))
        selector = QComboBox()
        selector.addItems(("All types", *types))
        controls.addWidget(selector)
        controls.addStretch()
        layout.addLayout(controls)
        message = text_label("", "muted")
        layout.addWidget(message)
        headers = ("Type", "Process path", "SHA-256", "Child processes") if key == "process" else ("Type", "Value", "Details")
        view = table(headers)
        view.setColumnWidth(0, 230 if key == "process" else 140)
        view.setColumnWidth(1, 320)
        if key == "process":
            view.setColumnWidth(2, 220)
        layout.addWidget(view, 1)
        self.filters[key], self.views[key], self.messages[key] = selector, view, message
        selector.currentTextChanged.connect(partial(self.filter_exclusions, key))
        self.tabs.addTab(panel, f"{title} ({len(self.records[key])})")
        self.filter_exclusions(key)

    def exclusion_rows(self, key, records):
        """Format decoded values consistently for display, copying, and text exports."""
        if key == "process":
            return [(" / ".join(record.types), record.value or "—", record.sha256 or "—", record.children or "—")
                    for record in records]
        return [(" / ".join(record.types), record.value, record.details) for record in records]

    def filter_exclusions(self, key, selected=None):
        """Filter by decoded type without discarding unknown entries or the original encoding."""
        selected = self.filters[key].currentText()
        records = self.records[key]
        visible = [record for record in records if selected == "All types" or selected in record.types]
        view = self.views[key]
        fill_table(view, self.exclusion_rows(key, visible))
        for row, record in enumerate(visible):
            detail = "\n".join(value for value in (record.raw, record.details) if value)
            view.item(row, 0).setToolTip(detail)
        message = f"Showing {len(visible)} of {len(records)} configured rules."
        if key == "general" and selected == "IOC":
            message = "IOC rules are unavailable in these local lists. Check the Secure Endpoint console."
        self.messages[key].setText(message)

    def save_results(self):
        """Export both complete lists with decoded columns, details, and original entries."""
        sections = []
        for title, key in (("Exclusions", "general"), ("Process exclusions", "process")):
            view = self.views[key]
            headers = [view.horizontalHeaderItem(i).text() for i in range(view.columnCount())]
            if key == "process":
                headers.append("Details")
            lines = [title, "\t".join([*headers, "Stored entry"])]
            for values, record in zip(self.exclusion_rows(key, self.records[key]), self.records[key]):
                fields = (*values, record.details) if key == "process" else values
                lines.append("\t".join((*fields, record.raw)))
            sections.append("\n".join(lines))
        save_text(self, "\n\n".join(sections))


class LinksDialog(ResultDialog):
    """Provide the existing documentation links in an aligned, keyboard-accessible list."""

    def __init__(self, parent=None):
        """Build descriptive link buttons without embedding implementation details."""
        super().__init__("Useful links", parent)
        links = (
            ("Secure Endpoint documentation", "https://console.amp.cisco.com/help/en/Content/Secure_Endpoint_User_Guide/Documentation.html"),
            ("API documentation", "https://developer.cisco.com/docs/secure-endpoint/"),
            ("Cisco Community", "https://community.cisco.com/t5/security-knowledge-base/tkb-p/4561-docs-security"),
            ("Exclusion best practices", "https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/213681-best-practices-for-amp-for-endpoint-excl.html"),
            ("Required server addresses", "https://www.cisco.com/c/en/us/support/docs/security/sourcefire-amp-appliances/118121-technote-sourcefire-00.html"),
            ("Required root certificates", "https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/216943-list-of-root-certificates-required-for-a.html"),
            ("Buy me a coffee", "https://www.buymeacoffee.com/mafranks"),
        )
        for title, url in links:
            self.body.addWidget(button(title, partial(webbrowser.open, url)))
        self.body.addStretch()
        self.finish_layout()
