# Secure Endpoint Health Checker for Windows

This tool helps inspect Cisco Secure Endpoint connector health, scan activity, policy settings, and connectivity on Windows. It is a side project and is not an officially supported Cisco product. Support and fixes are provided on a best-effort basis.

If you've found this beneficial and want continual updates, please say thanks with a cup of coffee!

[Support this project](https://www.buymeacoffee.com/mafranks)

## Introduction

Secure Endpoint performs file checks in the background. The Health Checker makes that activity visible through live scan events, process rankings, analysis reports, and policy diagnostics. It helps users investigate performance, connectivity, and configuration issues before collecting evidence for a support case.

Originally developed by Matthew Franks and Brandon Macer.

## October 2026 interface updates

- A resizable Qt dashboard with status cards, background operations, and readable light/dark themes.
- A **Dark mode: On/Off** toggle that saves your choice and applies it to every tool window.
- Read-only local policy exclusion lists with complete entry copying and text exports.
- Full-screen tool windows, selectable results, clipboard copying, and complete text exports.
- A standalone connectivity test that can run without a connector or API credentials.
- A local certificate viewer with fingerprints and separate current, historical, and future validity categories.

## Installation

The repository contains source and synthetic test fixtures. Build Windows executables locally; runtime configuration, logs, diagnostics, and generated binaries are excluded from version control.

The source GUI uses [PySide6 (Qt for Python)](https://doc.qt.io/qtforpython-6/gettingstarted.html). The project's runtime requirements target **64-bit Python 3.10–3.15**. Qt 6.12 supports **Windows 10 (1809 or later) and Windows 11**; see [Qt's Windows platform requirements](https://doc.qt.io/qt-6/windows.html). Install the versions selected by `requirements.txt`, which allows PySide6 6.x releases from 6.12 onward. No PySimpleGUI account or license key is required.

Configure `.env` as described in [API Credentials](#api-credentials) before launching the connector tools. Connectivity Test and Certificate viewer can run without that configuration.

Start from a fresh checkout, create a local configuration file, then install and run the source:

```powershell
git clone https://github.com/mafranks/CSE_Health_Checker.git
cd CSE_Health_Checker
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main_page.py
```

Check `python --version` first so the environment uses the interpreter you intend to run. Enable connector debug through the Secure Endpoint GUI before collecting scan activity. Keep your `.env` file in the working directory.

To build a Windows executable, run these commands **on Windows**:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m PyInstaller --clean main_page.spec
```

The rebuilt executable is `dist\SE_Health_Checker.exe`. Build dependencies are separate from runtime requirements.

To update an existing checkout and test the current source on your VM:

```powershell
git pull --ff-only
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main_page.py
```

Create the virtual environment first if it does not exist. Rebuild the executable after updating if you prefer running the packaged tool.

## Usage

Ensure Secure Endpoint is installed and running, then start `main_page.py` or the rebuilt executable as Administrator. The dashboard groups connector health, definitions/policy, and tools into aligned cards. Cards stack vertically on smaller windows; the dashboard scrolls while utility controls stay accessible. Qt handles display scaling automatically.

The **Dark mode: On/Off** toggle at the top right switches the dashboard and all tool windows between light and dark themes immediately. The app follows the system appearance until you choose a mode; your selection is then saved for future launches. Both themes include readable card titles, status badges, tables, text reports, and controls.

Live scan rankings use a resizable table, and analysis categories use tabs. Every tool window has a **Full screen** button and supports **F11**. **Escape** leaves full screen first; a second Escape closes the tool. Native maximize is also available. Slow API, connectivity, file-analysis, and diagnostic operations run in a serialized background queue, keeping the interface responsive and preventing concurrent changes to connector data. Closing waits for active work to finish.

Select table rows and press **Ctrl+C** to copy complete values as tab-separated text. Right-click a cell and choose **Copy value** to copy just its full path or value, even when the display shortens it. Ctrl/Shift selections allow multiple rows, and selections follow their records during live refresh. Text reports and source-log labels also support copying. Results remain read-only.

The app screenshots below are rendered from the current Qt interface with illustrative offline data. They show the layout and controls, rather than a particular endpoint's findings. Windows fonts and window decorations may differ. Normal startup reads the installed connector, XML, registry, logs, and APIs; setup failures display an error. See [screenshot generation](images/readme.md) for the fixture source and rendering commands.

## Main Page GUI

**Light mode**

![Dashboard in light mode with connector health, policy checks, tools, and the theme toggle](images/Main_Page.png)

**Dark mode**

![Dashboard in dark mode with the saved Dark mode toggle enabled](images/Main_Page_Dark.png)

### SE Version

This displays the installed Secure Endpoint connector version.

### CPU Usage

This displays the CPU resources being consumed by the SE process.

### SE Uptime

This displays the length of time since the SE process was started/restarted.

### Isolation

This displays either Not Isolated or Isolated depending on the current isolation status.

### Isolation Unlock Code

If isolated, the Isolation Code to unlock the connector will be displayed.

![Connector health card showing an illustrative isolation unlock code](images/Isolation_Code.png)

NOTE: Valid Secure Endpoint API Credentials are required for this functionality to work.

For additional information on Endpoint Isolation, please refer to the [Secure Endpoint User Guide](https://console.amp.cisco.com/help/en/Content/Secure_Endpoint_User_Guide/Documentation.html).

### TETRA Version

This displays the connector's installed TETRA definition version and automatically checks it against the cloud when the Health Checker starts. The check runs in the background and does not require API credentials. Click **Check version** beside TETRA to check again. Green indicates that the installed definition number is current or up to five numbers behind the cloud value. Yellow indicates older or unavailable definitions, or a lookup failure. A disabled TETRA engine can appear as **DISABLED** in red. The latest cloud version is displayed below the installed version after a successful check. If the lookup fails, the reason appears below the version and the manual check remains available for retrying.

![Definitions and policy card with installed and latest cloud versions](images/TETRA_Version.png)

NOTE: This functionality does not require API Credentials.

### Policy Serial

This displays the current Policy Serial number in place on the local connector. Use Check version next to Policy serial to check that against the version available in the cloud. If you have the latest version, it will be highlighted Green. If your version is not the latest, it will be highlighted Red. Also, the latest version available will be displayed after the check.

Click Check version next to Policy serial. The check refreshes the installed policy GUID and serial, then requests the cloud policy over HTTPS. If the local policy GUID returns 404, the tool checks the connector's current cloud assignment and retries with that policy when its GUID differs. Lookup failures and differing local/cloud policy identifiers appear Yellow with an explanation; Red is reserved for a verified serial mismatch on the same policy. Valid API credentials do not establish that a particular policy or connector is accessible in the selected organization and region.

NOTE: Requires Secure Endpoint API Credentials.

### API Credentials

The **API credentials** field shows **Valid** or **Invalid** for the Secure Endpoint credentials. API-backed policy and isolation checks need credentials for the selected deployment and region. When a local `policy.xml` cannot be read, the public-cloud policy retrieval path also uses Secure Client/XDR credentials and the matching organization name.

Copy `.env.example` to `.env` in the working directory used to launch the tool, then enter your own credentials locally. `.env` is ignored by Git; only the blank example belongs in the repository.

**Public Cloud**

```dotenv
CLIENT_ID="your-secure-endpoint-client-id"
API_KEY="your-secure-endpoint-api-key"
SX_CLIENT_ID="your-secure-client-or-xdr-client-id"
SX_API_KEY="your-secure-client-or-xdr-api-key"
ORG_NAME="Your organization name"
REGION="NAM"
```

Use `NAM`, `EU`, or `APJC` for `REGION`. Generate `CLIENT_ID` and `API_KEY` in the Secure Endpoint console, and the `SX_` credentials in the matching Secure Client/XDR regional console. The `SX_` variable names are retained by the tool. See Cisco’s public [API authentication guide](https://developer.cisco.com/docs/secure-endpoint/authentication/) for the integration and API-client setup. Set `ORG_NAME` to the organization associated with the Secure Endpoint deployment; it must match an organization returned for those credentials.

**Private Cloud**

```dotenv
CLIENT_ID="your-private-cloud-client-id"
API_KEY="your-private-cloud-api-key"
REGION="PC"
PC_DOMAIN="example.local"
PC_CA_PATH="C:/Users/your-user/Desktop/rootCA.crt"
```

Use the Private Cloud console's credentials, enter the domain without `https://`, and provide the path to its root CA certificate. Restart the tool after changing credentials or region.

**Optional proxy**

```dotenv
PROXIES='{"http": "http://proxy.example:3128", "https": "http://proxy.example:3128"}'
```

If authentication is required, use a URL such as `http://user:password@proxy.example:3128`. URL-encode special characters in the username or password. Connectivity Test supports HTTP CONNECT proxy URLs and displays invalid proxy settings before starting checks.

### Live paths / processes

Open **Live paths / processes** to see **Count**, **Process**, and **File path** for each unique process/file-path pair, ranked by the highest scan count. Repeated scans of the same pair increase its count instead of adding duplicate rows. The view also includes connector CPU usage, scan activity counters, the selected source log, and an explicit collection status.

![Live process and file-path rankings with scan counts and collection controls](images/Live_Debugging.png)

Press **Start / Resume** to begin collection, **Pause** to stop polling, and **Start / Resume** to continue with the existing counts. **Reset data** clears collected counters and results without rereading old log records. The table previews the top 500 unique pairs, using counts from all collected events. **Save results…** exports every unique pair and its count, including pairs beyond the preview limit. **Close** returns to the dashboard.

### Live Top Processes

**Live top processes** starts collecting automatically and ranks the top 100 processes from collected scan events. It uses the same pause, resume, reset, and save controls as the live event view. Export includes all collected process rankings.

![Live process rankings with scan counts and collection controls](images/Live_Top_Processes.png)

### Connectivity Test

Connectivity Test runs even when Secure Endpoint is not installed or running and does not require API credentials or Administrator access. Connector initialization errors appear inline; Connectivity Test remains available while connector-dependent tools are disabled.

Choose NAM, EU, APJC, or PC in the test window. Optional `REGION`, `PC_DOMAIN`, and `PROXIES` values from `.env` prefill the settings; without a region, NAM is the visible default. For PC, enter the Private Cloud domain. The checker uses a subset of the public-cloud hosts in Cisco’s [published server-address reference](https://www.cisco.com/c/en/us/support/docs/security/sourcefire-amp-appliances/118121-technote-sourcefire-00.html) and reports progress and Connected/Connection failed text for each host. Checks have network timeouts and stop between hosts when the window closes.

This is a DNS/TCP/TLS reachability check on port 443, rather than an API-authentication or certificate-trust check. The optional proxy setting supports HTTP CONNECT URLs, including URL-encoded usernames/passwords. Proxy configuration errors are displayed before any connections begin.

![Connectivity results with selectable region and per-host connection status](images/Connectivity.png)

The test reports reachability and does not verify the server certificate chain.

### View Exclusions

**View exclusions** shows the general and process lists read from the loaded policy. Both tabs preserve complete stored entries, including unrecognized values, and **Save all tabs…** exports both lists. Confirm rule types, executable exclusions, and child-process scope in the Secure Endpoint console.

The local list locations are also used by the [public upstream collector](https://github.com/CiscoSecurity/amp-05-health-checker-windows/blob/master/data.py). See Cisco’s public [exclusion guide](https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/213681-best-practices-for-amp-for-endpoint-excl.html) for exclusion behavior. This local view does not establish the complete cloud configuration.

![Read-only stored policy exclusion entries](images/View_Exclusions.png)

![Stored process exclusion entries in dark mode](images/View_Process_Exclusions_Dark.png)

### Generate Diagnostic

**Generate diagnostic** launches the connector's Support Diagnostic Tool and copies `amp_health_checker_log.log` from the working directory to the Desktop. The **Diagnostic started** message confirms the launch; wait for the Support Diagnostic Tool to finish collecting its bundle. If the launch fails, use **Support Diagnostic Tool** from the Windows Start menu.

When investigating an issue, select **DEBUG** in **Tool log level**, reproduce it, and collect the diagnostic and Health Checker log locally. **Feedback** opens this repository’s [issue form](https://github.com/mafranks/CSE_Health_Checker/issues/new). Include reproduction steps and redacted errors in public issues. Keep credentials, full diagnostics, policy XML, and endpoint identifiers out of GitHub uploads.

### Run Analysis

**Run analysis** displays six tabs: **Processes**, **Paths**, **Extensions**, **Folders**, **Exclusions hit**, and **IPs**. The view refreshes as connector log data is collected; **Refresh results** requests an immediate update. **Save results…** exports every tab, including IPs.

![Run Analysis with selectable ranking tabs and complete text export](images/Run_Analysis.png)

NOTE: The logs need to be in debug to show the appropriate data.

### Top IPs

The **IPs** analysis tab ranks addresses extracted from the connector log. These results describe the log records the checker collected.

### Engine status

**Engine status** shows read-only **Enabled**, **Disabled**, or **Unknown** values from the loaded policy. The table includes SHA, TETRA, Exploit Prevention, Network Monitoring, System Process Protection, ETHOS, SPERO, Orbital, Endpoint Isolation, Device Control, and Host Firewall. These rows describe policy settings.

![Read-only engine policy settings with enabled and disabled values](images/Check_Engines.png)

### Certificate viewer

**Certificate viewer** reads certificate-only PEM, CER, CRT, or DER files that you select locally. It shows each certificate's common name, issuer, SHA-1 and SHA-256 fingerprints calculated from DER, and exact UTC validity dates. It works without a connector or API credentials.

![Local certificate viewer with fingerprints and separate validity-date tabs](images/Certificate_Viewer.png)

**Valid dates** contains certificates within their validity period; **Historical** contains expired certificates. **Not yet valid** appears when needed. **Save all tabs…** exports all categories. Date validity does not establish Windows trust, revocation status, or whether a signer is accepted by Secure Endpoint. The viewer ships with no signer catalog and does not change certificate stores. Files containing PEM private keys are rejected.

### Manual SFC Analysis

**Manual SFC analysis** reads an independent snapshot of an `sfc.exe.log` file, including logs copied from another machine. The connector's current log is selected initially. Click **Choose SFC log…** to select another file, then **Analyze** to populate the results. **Use connector log** selects the default source again. Selecting or analyzing a manual log does not change the live collector's source or results.

![Manual SFC Analysis with log selection, analysis tabs, and source status](images/Manual_Analysis.png)

### Log Level

The Tool log level dropdown allows you to select the logging level for the SE Health Checker tool. It does not change the log level on the SE Connector! If you run into an issue with the Health Checker tool, please put the tool in DEBUG, reproduce the issue, and provide the SE diagnostic file and Health Checker logs for analysis.

The main window shows **Connector debug** as **Unknown (check connector GUI)**. Confirm or enable runtime debug logging in Secure Endpoint before collecting scan activity. **Tool Log Level** controls only `amp_health_checker_log.log`.

Manage connector debug through the Secure Endpoint GUI or Cisco’s [documented command-line interface](https://www.cisco.com/c/en/us/support/docs/security/amp-endpoints/213690-amp-for-endpoint-command-line-switches.html). The checker reads connector configuration and logs without automatically changing connector debug settings.

The live and analysis windows display the selected `sfc.exe.log` path. `RUNNING` means file/process scan records have been collected. `WAITING FOR SCAN EVENTS`, `EMPTY LOG`, and `LOG READ ERROR` explain why results are missing. The tool prefers the running connector's directory; if process inspection is unavailable, it logs a warning and uses the latest valid installation.

Log reading includes existing history and follows new complete lines without recounting them. Manual SFC Analysis uses an independent snapshot, so selecting another file or analyzing it repeatedly does not alter live results.

Build executables from the current source on Windows. Generated executables and diagnostic data are excluded from version control.

### Developer tests

Run the regression suite from the repository directory:

```shell
python -m unittest discover -s tests -v
```

Install `requirements.txt` first. The tests use real Qt widgets with an offscreen platform, temporary logs/settings, and stub Windows/API services, so they can run without a connector, API credentials, or a visible desktop. They cover light/dark themes, saved appearance, stored exclusion entries, layout resizing, background work, exports, manual snapshots, live pause/resume, policy failures, and shutdown while operations are active. Validate the actual GUI and connector diagnostic tools on Windows before distributing a rebuilt executable.

Regenerate illustrative screenshots with the following commands. The renderer uses synthetic data and mocked services; it does not connect to a live endpoint or cloud account.

```shell
python tests/render_gui.py --output images --theme light
python tests/render_gui.py --output /tmp/cse-dark-previews --theme dark
```

For the README's dark screenshots, copy `Main_Page.png` and `View_Process_Exclusions.png` from the dark output directory to `images/Main_Page_Dark.png` and `images/View_Process_Exclusions_Dark.png`. See [the image directory guide](images/readme.md) for the screenshot inventory.

### Region

Set `REGION` in `.env` to NAM, EU, APJC, or PC as described above. Restart the tool after changing the region.

### Refresh

**Refresh** reloads the existing connector state and resets collected statistics. If connector setup failed, it retries initialization. The dashboard also polls while no tool dialog or operation owns collection.

### Close

Close waits for active work to finish. Closing a tool dialog returns to the dashboard.
