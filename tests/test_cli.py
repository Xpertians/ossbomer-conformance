import unittest
import json
import os
import subprocess

class TestSBOMCLI(unittest.TestCase):

    def setUp(self):
        # Create a temporary SBOM file
        self.sbom_file = "test_sbom.json"
        sbom_data = {
            "componentName": "example-package",
            "supplier": "Example Corp",
            "version": "1.0.0",
            "hashes": "sha256:123456...",
            "license": "MIT",
            "vulnerabilityDisclosureURL": "https://example.com/vulns",
            "metadata": "Valid metadata"
        }
        with open(self.sbom_file, "w") as f:
            json.dump(sbom_data, f)
        self.rules_file = "config.json"
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

    def tearDown(self):
        for file in [self.sbom_file, self.rules_file]:
            if os.path.exists(file):
                os.remove(file)

    def test_cli_validate_valid_sbom(self):
        result = subprocess.run(["python3", "-m", "ossbomer_conformance.cli",
                                 "--file", self.sbom_file,
                                 "--rules", self.rules_file],
                                capture_output=True, text=True)
        self.assertIn("NTIA: Pass", result.stdout)
        self.assertIn("CRA: Pass", result.stdout)

    def test_cli_invalid_file_format(self):
        invalid_sbom_file = "invalid.sbom"
        with open(invalid_sbom_file, "w") as f:
            json.dump({}, f)
        result = subprocess.run(["python3", "-m", "ossbomer_conformance.cli",
                                 "--file", invalid_sbom_file,
                                 "--rules", self.rules_file],
                                capture_output=True, text=True)
        output = result.stdout + result.stderr
        self.assertIn("Unsupported file format", output)
        os.remove(invalid_sbom_file)

if __name__ == "__main__":
    unittest.main()
