import unittest

class EnterpriseMetadataTests(unittest.TestCase):
    def test_validator_must_exist(self):
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / 'tools' / 'enterprise_metadata.py'
        self.assertTrue(path.is_file(), 'enterprise metadata verifier is required')

if __name__ == '__main__':
    unittest.main()
