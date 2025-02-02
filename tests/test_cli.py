import unittest
import subprocess
import json
import os

class TestSBOMCLI(unittest.TestCase):
    def setUp(self):
        self.mock_rules = {
              "NTIA": {
                "required_fields": [
                  "supplier", "componentName", "version", "otherUniqueIdentifiers",
                  "dependencyRelationship", "author", "timestamp"
                ],
                "mappings": {
                  "cyclonedx": {
                    "supplier": "metadata.component.publisher",
                    "alt_supplier": "metadata.tools[0].vendor",
                    "componentName": "metadata.component.name",
                    "version": "metadata.component.version",
                    "otherUniqueIdentifiers": "metadata.component.purl",
                    "dependencyRelationship": "dependencies",
                    "author": "metadata.tools[0].name",
                    "timestamp": "metadata.timestamp"
                  }
                }
              },
              "CRA": {
                "required_fields": [
                  "componentCreator", "componentName", "version", "otherUniqueIdentifiers",
                  "dependencyRelationship", "author", "timestamp", "license",
                  "hashExecutableComponent", "sbomURI", "sourceCodeURI",
                  "uriExecutableComponent", "hashSourceCodeComponent"
                ],
                "mappings": {
                  "cyclonedx": {
                    "componentCreator": "metadata.component.publisher",
                    "componentName": "metadata.component.name",
                    "version": "metadata.component.version",
                    "otherUniqueIdentifiers": "metadata.component.purl",
                    "dependencyRelationship": "dependencies",
                    "author": "metadata.tools[0].name",
                    "timestamp": "metadata.timestamp",
                    "license": "metadata.component.licenses[0].license.id",
                    "hashExecutableComponent": "metadata.component.hashes",
                    "sbomURI": "metadata.component.sbomUri",
                    "sourceCodeURI": "metadata.component.sourceUri",
                    "uriExecutableComponent": "metadata.component.uri",
                    "hashSourceCodeComponent": "metadata.component.hashSourceCodeComponent"
                  }
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
