"""Interpret connector logging configuration without changing connector files."""

from dataclasses import dataclass
import math
from typing import Optional, Tuple
import xml.etree.ElementTree as ET


LOG_ERROR = 3
LOG_INFO = 6
LOG_SOURCE_USER = 3
DEFAULT_PERSISTENCE_SECONDS = 900
SOURCE_NAMES = {2: "crash recovery", 3: "local setting", 4: "debug pipe", 5: "remote request"}
SETTING_NAMES = (
    "level", "minimum_logging_persistence_duration_s",
    "local_level", "local_source", "local_time_set",
)


@dataclass(frozen=True)
class ConnectorLogState:
    """Keep inferred debug state separate from permission to create a temporary override."""

    enabled: Optional[bool]
    source: str
    detail: str
    may_enable: bool = False
    override: Optional[Tuple[int, int, int]] = None
    expires_at: Optional[int] = None


def integer_setting(value, name):
    """Validate signed 64-bit configuration values, treating -1 as the missing sentinel."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"Invalid connector logging setting: {name}")
    try:
        result = int(value)
    except ValueError as error:
        raise ValueError(f"Invalid connector logging setting: {name}") from error
    if not -1 <= result <= (1 << 63) - 1:
        raise ValueError(f"Invalid connector logging setting: {name}")
    return None if result == -1 else result


def logging_settings_from_root(root):
    """Read agent logging fields from unsigned or namespace-qualified configuration XML."""
    if root is None:
        return {}
    log = root.find(".//{*}agent/{*}log")
    settings = {name: log.findtext("{*}" + name) for name in SETTING_NAMES} if log is not None else {}
    count = root.findtext(".//{*}agent/{*}counter/{*}consecutive_unclean_shutdown_count")
    if count is not None:
        settings["consecutive_unclean_shutdown_count"] = count
    return settings


def read_logging_settings(path):
    """Read logging fields without mutating the application's cached policy XML."""
    return logging_settings_from_root(ET.parse(path).getroot())


def local_override(settings):
    """Validate the connector's persisted severity, source, and timestamp as one record."""
    names = ("local_level", "local_source", "local_time_set")
    values = tuple(integer_setting(settings.get(name), name) for name in names)
    if all(value is None for value in values):
        return None
    level, source, timestamp = values
    if any(value is None for value in values):
        raise ValueError("The saved connector logging setting is incomplete")
    if level not in range(1, LOG_INFO + 1) or source not in SOURCE_NAMES:
        raise ValueError("The saved connector logging setting is unsupported")
    return level, source, timestamp


def resolve_logging_state(policy, local, defaults, now, started_at=None):
    """Apply current policy conversion and preserve local overrides whose runtime is uncertain."""
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
        raise ValueError("Invalid time for connector logging evaluation")
    try:
        override = local_override(local)
        raw_level = policy.get("level")
        if raw_level is None:
            raw_level = defaults.get("level", "0")
        level = integer_setting(raw_level, "level")
        policy_debug = level is not None and level != 0
        if override is None:
            if not policy_debug:
                recovery = crash_recovery_state(policy, local, defaults, now, started_at)
                if recovery is not None:
                    return recovery
            detail = "Debug logging is enabled by policy." if policy_debug else "Debug logging is disabled by policy."
            return ConnectorLogState(policy_debug, "policy", detail, may_enable=not policy_debug)
        raw_duration = policy.get("minimum_logging_persistence_duration_s")
        if raw_duration is None:
            raw_duration = defaults.get("minimum_logging_persistence_duration_s", DEFAULT_PERSISTENCE_SECONDS)
        duration = integer_setting(raw_duration, "minimum_logging_persistence_duration_s")
        severity, source, timestamp = override
        if duration is None:
            return ConnectorLogState(None, SOURCE_NAMES[source], "The saved logging lifetime is unavailable; existing settings are preserved.", override=override)
        expires_at = timestamp + duration
        if int(now) > expires_at:
            return ConnectorLogState(None, "expired setting", "The saved logging window expired; verify the connector's current debug setting.", override=override, expires_at=expires_at)
        enabled = severity == LOG_INFO
        detail = ("Existing connector debug logging is preserved." if enabled else
                  "An existing logging override disables debug; use the connector's debug control to enable it.")
        return ConnectorLogState(enabled, SOURCE_NAMES[source], detail, override=override, expires_at=expires_at)
    except ValueError as error:
        return ConnectorLogState(None, "unknown", str(error))


def crash_recovery_state(policy, local, defaults, now, started_at):
    """Preserve automatic crash-recovery debug even when no manual override was saved."""
    raw_count = local.get("consecutive_unclean_shutdown_count", defaults.get("consecutive_unclean_shutdown_count"))
    count = integer_setting(raw_count, "consecutive_unclean_shutdown_count")
    if count is None or not 3 <= count <= 7:
        return None
    raw_duration = policy.get("minimum_logging_persistence_duration_s")
    if raw_duration is None:
        raw_duration = defaults.get("minimum_logging_persistence_duration_s", DEFAULT_PERSISTENCE_SECONDS)
    duration = integer_setting(raw_duration, "minimum_logging_persistence_duration_s")
    if duration is not None and isinstance(started_at, (int, float)) and math.isfinite(started_at):
        elapsed = int(now - started_at)
        if 0 <= elapsed <= duration:
            return ConnectorLogState(True, "crash recovery", "The connector's crash-recovery logging setting is preserved.")
    return ConnectorLogState(None, "crash recovery", "Crash-recovery logging may be active; existing connector settings are preserved.")
