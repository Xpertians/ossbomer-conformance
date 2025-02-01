import unittest
import json
import xml.etree.ElementTree as ET
from ossbomer_conformance.validator import SBOMConformanceValidator

class TestSBOMConformanceValidator(unittest.TestCase):
    def setUp(self):
        self.validator = SBOMConformanceValidator()

    def test_valid_cyclonedx_json(self):
        sbom_file = "tests/test_sbom.cyclonedx.1.4.json"
        with open(sbom_file, "r") as f:
            valid_cyclonedx_json = json.load(f)
        result = self.validator.validate_json(valid_cyclonedx_json)
        self.assertEqual(result["NTIA"]["status"], "Pass")
        self.assertEqual(result["CRA"]["status"], "Fail")

    def test_valid_cyclonedx_xml(self):
        sbom_file = "tests/test_sbom.cyclonedx.1.4.xml"
        tree = ET.parse(sbom_file)
        sbom_root = tree.getroot()
        result = self.validator.validate_xml(sbom_root)
        self.assertEqual(result["NTIA"]["status"], "Pass")
        self.assertEqual(result["CRA"]["status"], "Pass")

    def test_invalid_cyclonedx_json(self):
        invalid_cyclonedx_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "version": 1,
            "metadata": {}
        }
        result = self.validator.validate_json(invalid_cyclonedx_json)
        self.assertEqual(result["NTIA"]["status"], "Fail")
        self.assertIn("componentName", result["NTIA"]["missing_fields"])

    def test_invalid_cyclonedx_xml(self):
        invalid_cyclonedx_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:123e4567-e89b-12d3-a456-426614174000" version="1">
            <metadata>
            </metadata>
        </bom>"""
        
        sbom_root = ET.ElementTree(ET.fromstring(invalid_cyclonedx_xml)).getroot()
        result = self.validator.validate_xml(sbom_root)
        self.assertEqual(result["NTIA"]["status"], "Fail")
        self.assertIn("componentName", result["NTIA"]["missing_fields"])

if __name__ == "__main__":
    unittest.main()
