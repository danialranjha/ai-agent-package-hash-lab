import io
import unittest
import zipfile
import experiment as lab


class IntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result_data = lab.run_experiment()
        cls.rows = {(r['variant'], r['method']): r for r in cls.result_data['rows']}

    def test_complete_matrix(self):
        self.assertEqual(len(self.rows), 9)
        self.assertTrue(self.result_data['all_expectations_met'])

    def test_original_ordinary_twin(self):
        for method in lab.METHODS:
            row = self.rows['original', method]
            self.assertEqual(row['returncode'], 0)
            self.assertEqual(row['installed_value'], '42\n')

    def test_same_version_different_installed_bytes(self):
        row = self.rows['changed_data', 'version_only']
        self.assertEqual(row['package_version'], '1.0')
        self.assertEqual(row['returncode'], 0)
        self.assertEqual(row['installed_value'], '99\n')

    def test_trusted_hash_stops_before_install(self):
        for variant in ('changed_data', 'benign_metadata'):
            row = self.rows[variant, 'saved_hash']
            self.assertNotEqual(row['returncode'], 0)
            self.assertTrue(row['hash_mismatch'])
            self.assertEqual(row['installed_files'], [])
            self.assertIsNone(row['installed_value'])

    def test_rehash_is_not_trust(self):
        row = self.rows['changed_data', 'fresh_hash']
        self.assertEqual(row['expected_sha256'], row['archive_sha256'])
        self.assertNotEqual(row['expected_sha256'], self.result_data['original_sha256'])
        self.assertEqual(row['installed_value'], '99\n')
        self.assertEqual(row['returncode'], 0)

    def test_benign_metadata_is_different_bytes(self):
        for method in ('version_only', 'fresh_hash'):
            self.assertEqual(self.rows['benign_metadata', method]['installed_value'], '42\n')
        self.assertNotEqual(lab.digest(lab.wheel_bytes('original')),
                            lab.digest(lab.wheel_bytes('benign_metadata')))

    def test_pair_identity_and_hash_options(self):
        for variant in lab.VARIANTS:
            self.assertEqual(len({self.rows[variant, m]['archive_sha256'] for m in lab.METHODS}), 1)
            for method in lab.METHODS:
                row = self.rows[variant, method]
                self.assertIn('--no-index', row['command'])
                self.assertIn('--no-deps', row['command'])
                self.assertEqual('--require-hashes' in row['command'], method != 'version_only')

    def test_inert_deterministic_archives(self):
        for variant in lab.VARIANTS:
            data = lab.wheel_bytes(variant)
            self.assertEqual(data, lab.wheel_bytes(variant))
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                self.assertEqual(z.read('hash_fixture/__init__.py'), b'')
                self.assertEqual(len(z.namelist()), 5)
                self.assertFalse(any(n.endswith('.pth') or 'entry_points' in n for n in z.namelist()))
                self.assertNotIn(b'Requires-Dist', z.read('hash_fixture-1.0.dist-info/METADATA'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
