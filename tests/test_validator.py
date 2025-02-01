import unittest
import json
import os
from ossbomer_conformance.validator import SBOMConformanceValidator

class TestSBOMConformanceValidator(unittest.TestCase):

    def setUp(self):
        self.rules_file = "test_rules.json"
        test_rules = {
            "NTIA": {
                "required_fields": ["componentName", "supplier", "version", "hashes", "license"]
            },
            "CRA": {
                "required_fields": ["vulnerabilityDisclosureURL", "metadata"]
            }
        }
        with open(self.rules_file, "w") as f:
            json.dump(test_rules, f)
        self.validator = SBOMConformanceValidator(self.rules_file)

    def tearDown(self):
        if os.path.exists(self.rules_file):
            os.remove(self.rules_file)

    def test_validate_valid_sbom_json(self):
        sbom_data = {
            "componentName": "example-package",
            "supplier": "Example Corp",
            "version": "1.0.0",
            "hashes": "sha256:123456...",
            "license": "MIT",
            "vulnerabilityDisclosureURL": "https://example.com/vulns",
            "metadata": "Valid metadata"
        }
        result = self.validator.validate_json(sbom_data)
        self.assertEqual(result["NTIA"]["status"], "Pass")
        self.assertEqual(result["CRA"]["status"], "Pass")

    def test_validate_missing_fields_sbom_json(self):
        sbom_data = {
            "componentName": "example-package",
            "supplier": "Example Corp"
        }
        result = self.validator.validate_json(sbom_data)
        self.assertEqual(result["NTIA"]["status"], "Fail")
        self.assertIn("version", result["NTIA"]["missing_fields"])

    def test_validate_invalid_format_sbom(self):
        result = self.validator.validate_sbom("invalid.sbom")
        self.assertEqual(result["error"], "Unsupported file format. Only JSON and XML are supported.")

if __name__ == "__main__":
    unittest.main()
