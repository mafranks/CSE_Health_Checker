"""Read connector logs incrementally and parse file/process scan records."""

import locale
import logging
import os
import re


TIMESTAMP = re.compile(
    r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
)
WINDOWS_PATH_START = r"(?:\\\\\?\\(?:[A-Za-z]:\\|[^\\\s]+\\)|[A-Za-z]:\\|\\\\[^\\\s]+\\)"
SCAN_PATH = re.compile(
    r"(?P<path>" + WINDOWS_PATH_START + r".*?)\(\s*(?=" + WINDOWS_PATH_START + r")"
)
PATH_START = re.compile(WINDOWS_PATH_START)


def parse_scan_event(line):
    """Parse the existing three-path Event::Handle format with varied timestamps."""
    if not isinstance(line, str) or "Event::Handle" not in line:
        return None
    header, payload = line.split("Event::Handle", 1)
    timestamp = TIMESTAMP.search(header)
    path_match = SCAN_PATH.search(payload)
    if timestamp is None or path_match is None:
        return None
    remainder = payload[path_match.end():]
    paths = list(PATH_START.finditer(remainder))
    if len(paths) < 2:
        return None
    path = path_match.group("path").strip()
    process = remainder[paths[-1].start():].strip()
    path = normalize_log_path(path)
    process = normalize_log_path(process)
    if not path or not process:
        return None
    return {"time": timestamp.group(), "path": path, "process": process}


def normalize_log_path(path):
    """Remove the extended path prefix while preserving a UNC share's leading slashes."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    return path[4:] if path.startswith("\\\\?\\") else path


class SfcLogReader:
    """Follow complete log lines without repeating records across polls."""

    def __init__(self):
        """Initialize an unread log cursor and its user-visible read state."""
        self.reset()

    def reset(self):
        """Rewind the cursor for a fresh analysis or a different log file."""
        self.path = None
        self.identity = None
        self.offset = 0
        self.signature = b""
        self.error = ""
        self.empty = False

    def read_new_lines(self, path, include_partial=False):
        """Read a bounded snapshot, rewinding after replacement or truncation."""
        path = os.fspath(path)
        try:
            with open(path, "rb") as stream:
                stat = os.fstat(stream.fileno())
                identity = (stat.st_dev, stat.st_ino)
                if path != self.path or identity != self.identity:
                    self.reset()
                if stat.st_size < self.offset:
                    self.offset, self.signature = 0, b""
                if self.signature:
                    stream.seek(self.offset - len(self.signature))
                    if stream.read(len(self.signature)) != self.signature:
                        self.offset, self.signature = 0, b""
                stream.seek(self.offset)
                payload = stream.read(max(0, stat.st_size - self.offset))
                self.path, self.identity = path, identity
                self.empty = stat.st_size == 0
                self.error = ""
                end = len(payload) if include_partial else payload.rfind(b"\n") + 1
                complete = payload[:end]
                self.offset += end
                if complete:
                    self.signature = complete[-128:]
                encoding = locale.getpreferredencoding(False)
                return complete.decode(encoding, errors="replace").splitlines()
        except OSError as error:
            message = f"Unable to read SFC log {path}: {error}"
            if message != self.error:
                logging.warning(message)
            self.error = message
            return []
