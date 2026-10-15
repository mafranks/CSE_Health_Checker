"""Decode configured Windows exclusions without inferring types from filenames."""

from dataclasses import dataclass, replace
import re


EXCLUSION_TYPES = ("Threat", "Path", "File Extension", "Wildcard", "Executable", "IOC", "File Name", "Unknown")
PROCESS_TYPES = ("File Scan", "Malicious Activity Protection", "System Process Protection", "Behavioral Protection", "Unknown")
INFO_TYPES = {1: "Threat", 2: "Path", 3: "File Extension", 4: "File Name", 6: "Wildcard"}
# Accept both legacy and current System Process Protection encodings.
PROCESS_FLAGS = (("File Scan", 0x02, 0x01), ("Malicious Activity Protection", 0x10, 0x20),
                 ("System Process Protection", 0x44, 0x88), ("Behavioral Protection", 0x100, 0x200))


@dataclass(frozen=True)
class Exclusion:
    """Retain the rule's configured value, types, scope, and original encoding for copying."""

    types: tuple
    value: str
    details: str = ""
    sha256: str = ""
    children: str = ""
    raw: str = ""


def unknown_exclusion(raw, reason):
    """Keep malformed or unsupported rules visible without assigning a guessed category."""
    value = str(raw) if raw is not None and raw != "" else "(empty entry)"
    return Exclusion(("Unknown",), value, reason, raw=value)


def parse_info_exclusion(raw):
    """Decode version 256/258 threat, path, extension, filename, and regex rules."""
    if not isinstance(raw, str):
        return unknown_exclusion(raw, "Missing exclusion value")
    parts = raw.split("|")
    if len(parts) not in (5, 6) or not parts[4]:
        return unknown_exclusion(raw, "Incomplete or unsupported exclusion format")
    try:
        version, kind, subdirs, partial = map(int, parts[:4])
        engine = int(parts[5]) if len(parts) == 6 else 0
    except ValueError:
        return unknown_exclusion(raw, "Invalid exclusion fields")
    if version not in (256, 258) or subdirs not in (0, 1) or partial not in (0, 1):
        return unknown_exclusion(raw, "Unsupported version or path flags")
    details = []
    if kind == 2:
        details.append("Subfolders: Yes" if subdirs else "Subfolders: No")
        if partial:
            details.append("Partial path match")
    if kind == 6:
        details.append("Regular expression")
    if engine:
        details.append("Malicious Activity Protection" if engine == 16 else f"Engine ID: {engine}")
    if kind not in INFO_TYPES:
        details.append(f"Unsupported type ID: {kind}")
    return Exclusion((INFO_TYPES.get(kind, "Unknown"),), parts[4], "; ".join(details), raw=raw)


def process_scope(version, flags):
    """Resolve combined protection flags and child scope, including version-2 defaults."""
    if version in (1, 2) and flags in (0, 1):
        flags |= 0x02
    types, children, notes = [], [], []
    known = 0
    for name, protection, child in PROCESS_FLAGS:
        known |= protection | child
        if flags & protection:
            types.append(name)
            children.append(f"{name}: {'Yes' if flags & child else 'No'}")
        elif flags & child:
            notes.append(f"{name}: child flag without protection flag")
    if flags & ~known:
        notes.append(f"Unknown flags: 0x{flags & ~known:x}")
    if notes or not types:
        types.append("Unknown")
    return tuple(types), "; ".join(children), "; ".join(notes) or ("" if flags else "No protection flags set")


def parse_process_exclusion(raw):
    """Decode legacy and current process formats with path/hash and engine-specific scope."""
    if not isinstance(raw, str):
        return unknown_exclusion(raw, "Missing process exclusion value")
    parts = raw.split("|")
    try:
        version, auth = map(int, parts[:2])
    except ValueError:
        return unknown_exclusion(raw, "Invalid process exclusion fields")
    if version == 1:
        return parse_legacy_process(raw, parts, auth)
    if version not in (2, 3) or len(parts) != 6 or parts[-1] != "":
        return unknown_exclusion(raw, "Incomplete or unsupported process exclusion format")
    sha256, path = parts[2:4]
    try:
        flags = int(parts[4])
    except ValueError:
        return unknown_exclusion(raw, "Invalid process protection flags")
    if flags < 0 or flags > 0xffffffff or not valid_process_identity(auth, sha256, path):
        return unknown_exclusion(raw, "Invalid process identity or protection flags")
    types, children, notes = process_scope(version, flags)
    return Exclusion(types, path, notes, sha256 if auth == 1 else "", children, raw)


def valid_process_identity(auth, sha256, path):
    """Require a path for path authentication or a complete SHA-256 for hash authentication."""
    if auth == 0:
        return bool(path) and not sha256
    if auth == 1:
        return bool(re.fullmatch(r"[0-9a-fA-F]{64}", sha256))
    return False


def parse_legacy_process(raw, parts, auth):
    """Preserve version-1 path-only, hash-only, and path-plus-hash File Scan exclusions."""
    fields = parts[2:]
    if fields and fields[-1] == "":
        fields = fields[:-1]
    if auth == 0 and len(fields) == 1 and fields[0]:
        return Exclusion(("File Scan",), fields[0], "Legacy version 1", children="File Scan: No", raw=raw)
    if auth == 1 and len(fields) in (1, 2) and valid_process_identity(auth, fields[0], ""):
        return Exclusion(("File Scan",), fields[1] if len(fields) == 2 else "", "Legacy version 1",
                         fields[0], "File Scan: No", raw)
    return unknown_exclusion(raw, "Invalid legacy process exclusion")


def child_element(root, name):
    """Find a direct XML child by local name in signed, namespaced, or plain policies."""
    return next((child for child in root if child.tag.rsplit("}", 1)[-1] == name), None) if root is not None else None


def read_policy_exclusions(root):
    """Read standard exclusions and executable rules from Exploit Prevention v8 only."""
    if root is None:
        raise ValueError("A policy XML root is required")
    config = next((node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "config"), None)
    lists = {"path_exclusions": [], "process_exclusions": [], "executable_exclusions": []}
    exclusions = child_element(config, "exclusions")
    for tag, key in (("info", "path_exclusions"), ("process", "process_exclusions")):
        parent = child_element(exclusions, tag)
        if parent is not None:
            lists[key] = [node.text for node in parent if node.tag.rsplit("}", 1)[-1] == "item"]
    exprev = child_element(child_element(config, "agent"), "exprev")
    apps = child_element(child_element(exprev, "v8"), "exclude_app_list")
    if apps is not None and apps.text:
        lists["executable_exclusions"].extend((app.strip(), "v8") for app in apps.text.split("|") if app.strip())
    return lists


def process_display_entries(record):
    """Show each protection separately so its child-process cell contains a single Yes or No."""
    scopes = dict(scope.rsplit(": ", 1) for scope in record.children.split("; ") if scope)
    return [replace(record, types=(kind,), children=scopes.get(kind, "—")) for kind in record.types]


def configured_exclusions(policy):
    """Build one row per process protection and include unique v8 executable exclusions."""
    entries = policy_exclusion_entries(policy)
    general = [parse_info_exclusion(raw) for raw in entries["general"]]
    processes = [record for raw in entries["process"]
                 for record in process_display_entries(parse_process_exclusion(raw))]
    executables = dict.fromkeys(value for value, version in policy.get("executable_exclusions") or [] if version == "v8")
    general.extend(Exclusion(("Executable",), value, "Exploit Prevention: v8") for value in executables)
    return general, processes


def policy_exclusion_entries(policy):
    """Return complete copyable entries without guessing exclusion types or child scope."""
    if not isinstance(policy, dict):
        raise ValueError("A policy dictionary is required")
    result = {}
    for display, key in (("general", "path_exclusions"), ("process", "process_exclusions")):
        values = policy.get(key) or []
        if not isinstance(values, (list, tuple)):
            raise ValueError("Policy exclusion lists must contain a sequence of entries")
        result[display] = tuple(str(value) if value is not None and value != "" else "(empty entry)" for value in values)
    return result
