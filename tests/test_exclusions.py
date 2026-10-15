"""Verify lossless local policy list handling using synthetic XML."""

import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from exclusions import configured_exclusions, parse_info_exclusion, parse_process_exclusion, policy_exclusion_entries, read_policy_exclusions


class PolicyExclusionTests(unittest.TestCase):
    """Preserve complete entries and list boundaries without undocumented field decoding."""

    def test_plain_and_namespaced_lists_preserve_entries_and_empty_values(self):
        """Read the same general/process entries from signed and plain policy XML."""
        config = ('<config><exclusions><info><item>Example entry | with fields</item><item/></info>'
                  '<process><item>Example process entry</item></process></exclusions></config>')
        for xml in (config, '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Object>' + config + '</Object></Signature>'):
            with self.subTest(namespaced='xmlns' in xml):
                policy = read_policy_exclusions(ET.fromstring(xml))
                entries = policy_exclusion_entries(policy)
                self.assertEqual(entries['general'], ('Example entry | with fields', '(empty entry)'))
                self.assertEqual(entries['process'], ('Example process entry',))

    def test_absent_lists_remain_empty_and_unrelated_fields_are_ignored(self):
        """Avoid interpreting other configuration sections as exclusion lists."""
        root = ET.fromstring('<config><agent><other>Example setting</other></agent></config>')
        self.assertEqual(read_policy_exclusions(root), {'path_exclusions': [], 'process_exclusions': [], 'executable_exclusions': []})
        self.assertEqual(policy_exclusion_entries({}), {'general': (), 'process': ()})

    def test_invalid_inputs_are_rejected_before_display(self):
        """Reject missing roots and invalid list containers without dropping individual entries."""
        with self.assertRaises(ValueError):
            read_policy_exclusions(None)
        for policy in (None, [], {'path_exclusions': 'one string'}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                policy_exclusion_entries(policy)

    def test_backend_policy_loader_preserves_list_contents(self):
        """Exercise the actual collector to ensure complete local entries reach the viewer."""
        from test_health_checker import Data
        root = ET.fromstring('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Object><config>'
                             '<exclusions><process><item>Example process</item></process></exclusions>'
                             '</config></Object></Signature>')
        data = Data.__new__(Data)
        with patch.object(data, 'get_root', return_value=root):
            data.parse_xml('fixture.xml')
        self.assertEqual(data.policy_dict['process_exclusions'], ['Example process'])


class ExclusionParsingTests(unittest.TestCase):
    """Verify configured categories, legacy compatibility, hashes, and per-engine child flags."""

    def test_standard_types_come_from_policy_fields_not_value_suffixes(self):
        """Distinguish a threat, path, extension, filename, and wildcard even for identical values."""
        for kind, expected in ((1, "Threat"), (2, "Path"), (3, "File Extension"), (4, "File Name"), (6, "Wildcard")):
            with self.subTest(kind=kind):
                record = parse_info_exclusion(f"256|{kind}|0|0|example.exe")
                self.assertEqual(record.types, (expected,))
                self.assertEqual(record.value, "example.exe")

    def test_engine_specific_value_and_path_options_are_preserved(self):
        """Extract the value before an appended engine ID and retain declared path flags."""
        record = parse_info_exclusion(r"258|2|1|1|C:\Example\Cache|16")
        self.assertEqual(record.value, r"C:\Example\Cache")
        self.assertIn("Subfolders: Yes", record.details)
        self.assertIn("Partial path match", record.details)
        self.assertIn("Malicious Activity Protection", record.details)

    def test_regex_is_not_rewritten_as_a_path(self):
        """Keep the complete stored expression visible rather than changing matching semantics."""
        value = r"^[A-Za-z]\\Example\\.*\\cache"
        record = parse_info_exclusion("256|6|0|0|" + value)
        self.assertEqual(record.types, ("Wildcard",))
        self.assertEqual(record.value, value)
        self.assertEqual(record.details, "Regular expression")

    def test_common_process_flags_and_child_scope(self):
        """Verify every requested protection, legacy SPP bits, and modern SPP bits."""
        cases = ((2, 0, "File Scan", "No"), (2, 1, "File Scan", "Yes"),
                 (3, 2, "File Scan", "No"), (3, 3, "File Scan", "Yes"),
                 (3, 4, "System Process Protection", "No"), (3, 12, "System Process Protection", "Yes"),
                 (3, 64, "System Process Protection", "No"), (3, 192, "System Process Protection", "Yes"),
                 (3, 16, "Malicious Activity Protection", "No"), (3, 48, "Malicious Activity Protection", "Yes"),
                 (3, 256, "Behavioral Protection", "No"), (3, 768, "Behavioral Protection", "Yes"))
        for version, flags, expected, children in cases:
            with self.subTest(version=version, flags=flags):
                record = parse_process_exclusion(fr"{version}|0||C:\Example\app.exe|{flags}|")
                self.assertEqual(record.types, (expected,))
                self.assertEqual(record.children, f"{expected}: {children}")

    def test_combined_process_flags_keep_different_child_scopes(self):
        """Avoid applying one protection's child flag to every protection on a combined rule."""
        record = parse_process_exclusion(r"3|0||C:\Example\app.exe|52|")
        self.assertEqual(record.types, ("Malicious Activity Protection", "System Process Protection"))
        self.assertEqual(record.children, "Malicious Activity Protection: Yes; System Process Protection: No")

    def test_hash_only_and_hash_plus_path_process_exclusions(self):
        """Retain a full SHA-256 and avoid losing hash-only exclusions when the path is empty."""
        sha = "ab" * 32
        for path in ("", r"C:\Example\app.exe"):
            record = parse_process_exclusion(f"3|1|{sha}|{path}|256|")
            self.assertEqual(record.types, ("Behavioral Protection",))
            self.assertEqual(record.sha256, sha)
            self.assertEqual(record.value, path)

    def test_legacy_process_formats(self):
        """Support the documented version-1 path, hash-only, and path-plus-hash formats."""
        sha = "01" * 32
        for raw in (r"1|0|C:\Example\app.exe", f"1|1|{sha}", fr"1|1|{sha}|C:\Example\app.exe"):
            self.assertEqual(parse_process_exclusion(raw).types, ("File Scan",))

    def test_unsupported_entries_remain_visible(self):
        """Reject incomplete fields, unsupported IDs, invalid hashes, and unknown process versions."""
        for raw in (None, "", "256|2|0", "001|0|0|0|example", "256|99|0|0|example", "256|2|5|0|example"):
            with self.subTest(raw=raw):
                self.assertEqual(parse_info_exclusion(raw).types, ("Unknown",))
        for raw in (None, "", "9|0||app.exe|2|", "3|1|bad-hash||2|", "3|0||app.exe|-1|", "3|0||app.exe|2"):
            with self.subTest(raw=raw):
                record = parse_process_exclusion(raw)
                self.assertEqual(record.types, ("Unknown",))
                self.assertTrue(record.value)

    def test_unknown_flag_bits_do_not_hide_known_protections(self):
        """Show both the known protection and an explicit unknown marker for future flag bits."""
        record = parse_process_exclusion(r"3|0||C:\Example\app.exe|1026|")
        self.assertEqual(record.types, ("File Scan", "Unknown"))
        self.assertIn("0x400", record.details)
        self.assertEqual(parse_process_exclusion(r"3|0||app.exe|1|").types, ("Unknown",))


class TypedPolicyExclusionTests(unittest.TestCase):
    """Extract standard and executable exclusion lists from signed and plain policy XML."""

    def test_policy_lists_and_executable_versions(self):
        """Read both lists and show only v8 executables, ignoring rules unique to older versions."""
        config = (r"<config><exclusions><info><item>256|2|1|0|C:\Example\Cache</item></info>"
                  r"<process><item>2|0||C:\Example\app.exe|1|</item></process></exclusions>"
                  "<agent><exprev><v4><exclude_app_list>app.exe|other.exe</exclude_app_list></v4>"
                  "<v8><exclude_app_list>app.exe|app.exe</exclude_app_list></v8></exprev></agent></config>")
        for xml in (config, '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Object>' + config + '</Object></Signature>'):
            policy = read_policy_exclusions(ET.fromstring(xml))
            general, processes = configured_exclusions(policy)
            self.assertEqual([record.types for record in general], [("Path",), ("Executable",)])
            self.assertEqual(general[1].details, "Exploit Prevention: v8")
            self.assertEqual(general[1].value, "app.exe")
            self.assertEqual(policy["executable_exclusions"], [("app.exe", "v8"), ("app.exe", "v8")])
            self.assertEqual(processes[0].types, ("File Scan",))

    def test_older_exploit_prevention_versions_are_not_used_as_fallback(self):
        """Leave executable results empty when only older versions appear in XML or cached lists."""
        root = ET.fromstring("<config><agent><exprev><v4><exclude_app_list>old.exe</exclude_app_list></v4>"
                             "</exprev></agent></config>")
        self.assertEqual(read_policy_exclusions(root)["executable_exclusions"], [])
        general, _ = configured_exclusions({"executable_exclusions": [("old.exe", "v4")]})
        self.assertEqual(general, [])

    def test_empty_policy_lists_do_not_fabricate_rules(self):
        """Preserve empty lists and malformed items without implying that cloud IOC rules are absent."""
        policy = read_policy_exclusions(ET.fromstring("<config><exclusions><info><item/></info></exclusions></config>"))
        general, processes = configured_exclusions(policy)
        self.assertEqual(general[0].types, ("Unknown",))
        self.assertEqual(processes, [])
        self.assertEqual(policy["executable_exclusions"], [])
        with self.assertRaises(ValueError):
            read_policy_exclusions(None)

    def test_backend_policy_loader_includes_executable_settings(self):
        """Exercise the real Data loader so executable rules actually reach the viewer."""
        from unittest.mock import patch
        from test_health_checker import Data
        root = ET.fromstring('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Object><config>'
                             '<agent><exprev><v8><exclude_app_list>app.exe</exclude_app_list></v8></exprev></agent>'
                             '</config></Object></Signature>')
        data = Data.__new__(Data)
        with patch.object(data, "get_root", return_value=root):
            data.parse_xml("fixture.xml")
        self.assertEqual(data.policy_dict["executable_exclusions"], [("app.exe", "v8")])
