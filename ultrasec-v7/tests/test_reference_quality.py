"""Tests for the PUBLIC fixture only, not the proprietary V7 benchmark."""
import copy
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'verification'))
import reference_quality as q


class ReferenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = q.deterministic_fixture()
        cls.rows = cls.fixture['records']

    def test_public_fixture_schema(self):
        self.assertEqual(self.fixture['schema_version'], 1)
        self.assertEqual(self.fixture['scope'], 'PUBLIC_SYNTHETIC_GRAPH_REFERENCE_ONLY')
        self.assertEqual(len(self.rows), 48)

    def test_every_pair_has_two_distinct_graphs(self):
        result = q.validate_rows(self.rows)
        self.assertEqual(result['pairs'], 24)
        self.assertEqual(result['graphs_unique'], 48)
        self.assertEqual(result['languages'], {'python':16, 'javascript':16, 'go':16})

    def test_split_is_family_disjoint(self):
        for row in self.rows:
            self.assertEqual(row['split'], q.SPLITS[row['cwe']])

    def test_actual_reference_semantics(self):
        from collections import Counter
        counts = Counter()
        for row in self.rows:
            self.assertEqual(q.evaluate(row), row['label'] == 'vulnerable')
            counts[row['label']] += 1
        self.assertEqual(counts, {'vulnerable':24, 'mitigated':24})

    def test_reference_rebuild_byte_identical(self):
        expected = q.canonical(q.deterministic_fixture())
        self.assertEqual(expected, q.canonical(q.load_fixture()))
        self.assertEqual(q.load_manifest()['fixture_sha256'], q.sha256(expected))

    def test_fixture_integrity_from_disk(self):
        report=q.verify_fixture()
        self.assertEqual(report['records'], 48)
        self.assertEqual(report['cwe'],6)

    def test_mutants_killed(self):
        self.assertEqual(q.mutation_checks()['killed'], 48)

    def test_adversarial_suite(self):
        self.assertGreaterEqual(q.adversarial_checks()['adversarial_cases'], 100)

    def _changed(self, idx=0):
        return copy.deepcopy(self.rows[idx])

    def test_unknown_node(self):
        row=self._changed()
        row['nodes'][2]['kind']='unknown'
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_forward_reference_rejected(self):
        row=self._changed()
        row['nodes'][2]['inputs']=['boundary']
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_missing_input_rejected(self):
        row=self._changed()
        del row['nodes'][2]['inputs']
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_invalid_source_trust_rejected(self):
        row=self._changed()
        row['nodes'][0]['trust']='external'
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_source_with_edge_rejected(self):
        row=self._changed()
        row['nodes'][0]['inputs']=['trusted_context']
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_duplicate_node_ids_rejected(self):
        row=self._changed()
        row['nodes'][2]['id']='user_input'
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_missing_sink_rejected(self):
        row=self._changed()
        row['nodes'][-1]['kind']='forward'
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_nonterminal_sink_rejected(self):
        row=self._changed()
        row['nodes'][-2]['kind']='sink'
        row['nodes'][-2]['requires']=row['cwe']
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_wrong_sink_contract_rejected(self):
        row=self._changed()
        row['nodes'][-1]['requires']='CWE-79'
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_unknown_sanitizer_contract_rejected(self):
        row=self._changed()
        row['nodes'][-2]['protects']='something'
        with self.assertRaises(ValueError): q.evaluate(row)

    def test_wrong_sanitizer_not_a_fix(self):
        row=self._changed(1)
        row['nodes'][-2]['protects']='CWE-79'
        self.assertTrue(q.evaluate(row))

    def test_decoy_sanitizer_not_a_fix(self):
        row=self._changed(6)
        self.assertTrue(q.evaluate(row))
        fixed=self._changed(7)
        self.assertFalse(q.evaluate(fixed))

    def test_bad_record_id_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[1]['id']=rows[0]['id']
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_duplicate_graph_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[1]['nodes']=rows[0]['nodes']
        rows[1]['graph_sha256']=rows[0]['graph_sha256']
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_tampered_hash_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['graph_sha256']='0'*64
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_tampered_label_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['label']='mitigated'
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_bad_split_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['split']='test'
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_bad_cwe_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['cwe']='CWE-9999'
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_bad_language_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['language']='rust'
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_bad_pair_rejected(self):
        rows=copy.deepcopy(self.rows)
        del rows[0]
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_inconsistent_pair_split_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['pair_id']=rows[2]['pair_id']
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_bad_family_leak_rejected(self):
        rows=copy.deepcopy(self.rows)
        rows[0]['split']='validation'
        rows[1]['split']='validation'
        with self.assertRaises(ValueError):q.validate_rows(rows)

    def test_wrong_manifest_hash_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            fixture_path=root/'ultrasec-v7/fixtures'
            fixture_path.mkdir(parents=True)
            (fixture_path/'reference_pairs.json').write_bytes(q.canonical(self.fixture))
            wrong=q.load_manifest()
            wrong['fixture_sha256']='0'*64
            (fixture_path/'reference_manifest.json').write_bytes(q.canonical(wrong))
            with self.assertRaises(ValueError):q.verify_fixture(root)

    def test_inconsistent_manifest_counts_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            fixture_path=root/'ultrasec-v7/fixtures'
            fixture_path.mkdir(parents=True)
            (fixture_path/'reference_pairs.json').write_bytes(q.canonical(self.fixture))
            wrong=q.load_manifest()
            wrong['pairs']=25
            (fixture_path/'reference_manifest.json').write_bytes(q.canonical(wrong))
            with self.assertRaises(ValueError):q.verify_fixture(root)

    def test_security_status_explicit(self):
        self.assertEqual(q.load_manifest()['private_dataset_coverage'], 'NOT_TESTED')
        self.assertEqual(q.load_manifest()['certification'], 'NOT_CERTIFIED')

    def test_canonical_hash_deterministic(self):
        self.assertEqual(q.sha256(q.canonical(self.fixture)), q.sha256(q.canonical(q.deterministic_fixture())))
        self.assertEqual(len(q.sha256(b'example')),64)

    def test_public_only_self_review(self):
        report=q.static_self_review()
        self.assertEqual(report['jobs_checked'],7)

    def test_command_line_guards_are_actually_exercised(self):
        import contextlib
        import io
        from unittest import mock
        for gate in ('core', 'build', 'mutation', 'adversarial', 'self-review', 'reliability'):
            buf = io.StringIO()
            with self.subTest(gate=gate), mock.patch.object(sys, 'argv', ['reference_quality.py', gate]), contextlib.redirect_stdout(buf):
                q.main()
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload['gate'], gate)
            self.assertEqual(payload['scope'], 'PUBLIC_REFERENCE_FIXTURE_ONLY')
            self.assertEqual(payload['result'], 'PASS')

    def test_coverage_must_be_measured_not_claimed(self):
        from unittest import mock
        with mock.patch.object(sys, 'argv', ['reference_quality.py', 'coverage']):
            with self.assertRaises(SystemExit) as cm:
                q.main()
        self.assertIn('coverage command', str(cm.exception))



if __name__ == '__main__':
    unittest.main()