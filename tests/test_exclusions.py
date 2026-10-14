"""Verify lossless local policy list handling using synthetic XML."""

import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from exclusions import policy_exclusion_entries, read_policy_exclusions


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
        self.assertEqual(read_policy_exclusions(root), {'path_exclusions': [], 'process_exclusions': []})
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
