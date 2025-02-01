import unittest
import json
import xml.etree.ElementTree as ET
from ossbomer_conformance.validator import SBOMConformanceValidator

class TestSBOMConformanceValidator(unittest.TestCase):
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
        self.validator = SBOMConformanceValidator()
        self.validator.rules = self.mock_rules

    def test_valid_cyclonedx_json(self):
        valid_cyclonedx_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "version": 1,
            "metadata": {
                "timestamp": "2025-02-01T12:00:00Z",
                "tools": [{
                    "vendor": "Example Corp",
                    "name": "SBOM Generator",
                    "version": "2.0.0"
                }],
                "component": {
                    "type": "application",
                    "name": "SBOM Tool",
                    "version": "2.0.0",
                    "purl": "pkg:npm/sbom-tool@2.0.0",
                    "licenses": [{
                        "license": {"id": "Apache-2.0"}
                    }]
                }
            }
        }
        result = self.validator.validate_json(valid_cyclonedx_json)
        self.assertEqual(result["NTIA"]["status"], "Pass")
        self.assertEqual(result["CRA"]["status"], "Pass")

    def test_valid_cyclonedx_xml(self):
        valid_cyclonedx_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:123e4567-e89b-12d3-a456-426614174000" version="1">
            <metadata>
                <timestamp>2025-02-01T12:00:00Z</timestamp>
                <tools>
                    <tool>
                        <vendor>Example Corp</vendor>
                        <name>SBOM Generator</name>
                        <version>2.0.0</version>
                    </tool>
                </tools>
                <component type="application">
                    <name>SBOM Tool</name>
                    <version>2.0.0</version>
                    <purl>pkg:npm/sbom-tool@2.0.0</purl>
                    <licenses>
                        <license>
                            <id>Apache-2.0</id>
                        </license>
                    </licenses>
                </component>
            </metadata>
        </bom>"""
        
        sbom_root = ET.ElementTree(ET.fromstring(valid_cyclonedx_xml)).getroot()
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
