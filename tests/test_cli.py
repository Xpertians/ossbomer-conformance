import unittest
import subprocess
import json
import os

class TestSBOMCLI(unittest.TestCase):
    def setUp(self):
        self.mock_rules = {
            "NTIA": {
                "required_fields": ["componentName", "supplier", "version", "purl", "hashes", "license"],
                "mappings": {
                    "spdx": {"componentName": "name", "supplier": "supplier"},
                    "cyclonedx": {"componentName": "metadata/component/name", "supplier": "metadata/tools/tool/vendor"}
                }
            },
            "CRA": {
                "required_fields": ["vulnerabilityDisclosureURL", "metadata"],
                "mappings": {
                    "spdx": {"metadata": "creationInfo"},
                    "cyclonedx": {"metadata": "metadata/timestamp"}
                }
            }
        }
        self.rules_file = "tests/config.json"
        with open(self.rules_file, "w") as f:
            json.dump(self.mock_rules, f)
    
    def tearDown(self):
        if os.path.exists(self.rules_file):
            os.remove(self.rules_file)
    
    def test_cli_validate_valid_sbom(self):
        valid_sbom = "tests/test_sbom.cyclonedx.1.4.xml"
        result = subprocess.run([
            "python3", "-m", "ossbomer_conformance.cli",
            "--file", valid_sbom,
            "--rules", self.rules_file
        ], capture_output=True, text=True)
        self.assertIn("NTIA: Pass", result.stdout)
        self.assertIn("CRA: Pass", result.stdout)

if __name__ == "__main__":
    unittest.main()
