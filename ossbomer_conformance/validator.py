import json
import pkg_resources
import xml.etree.ElementTree as ET

class SBOMConformanceValidator:
    def __init__(self, rules_file="config.json"):
        rules_file = pkg_resources.resource_filename("ossbomer_conformance", "config.json")
        self.rules = self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        try:
            with open(rules_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError("Error: Invalid or missing rules file. Please provide a valid configuration file.")

    def detect_format(self, sbom_data):
        """Detect if SBOM is SPDX or CycloneDX"""
        if "SPDXID" in sbom_data or "spdxVersion" in sbom_data:
            return "spdx"
        if "bomFormat" in sbom_data and sbom_data["bomFormat"] == "CycloneDX":
            return "cyclonedx"
        return None  # Unknown format

    def get_nested_value(self, data, key_path):
        """Retrieve nested values from dictionaries & lists safely"""
        keys = key_path.split(".")
        value = data
        
        for key in keys:
            if "[" in key and "]" in key:
                key, index = key[:-1].split("[")
                index = int(index)
                value = value.get(key, [])
                if isinstance(value, list) and len(value) > index:
                    value = value[index]
                else:
                    return None
            elif isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None  # Key not found
        
        return value

    def normalize_fields(self, sbom_data, sbom_format, required_fields):
        """Convert SBOM fields to a common format using the mappings"""
        mappings = self.rules.get("NTIA", {}).get("mappings", {}).get(sbom_format, {})
        normalized_data = {}
        
        for required_field in required_fields:
            mapped_field = mappings.get(required_field, required_field)  # Default to same name if not mapped
            normalized_data[required_field] = self.get_nested_value(sbom_data, mapped_field)
        
        return normalized_data

    def validate_sbom(self, sbom_file):
        try:
            if sbom_file.endswith(".json"):
                with open(sbom_file, "r") as f:
                    sbom_data = json.load(f)
                return self.validate_json(sbom_data)
            elif sbom_file.endswith(".xml"):
                tree = ET.parse(sbom_file)
                root = tree.getroot()
                return self.validate_xml(root)
            else:
                return {"error": "Unsupported file format. Only JSON and XML are supported."}
        except Exception as e:
            return {"error": str(e)}
    
    def validate_json(self, sbom_data):
        sbom_format = self.detect_format(sbom_data)
        if not sbom_format:
            return {"error": "Could not determine SBOM format (SPDX or CycloneDX)"}

        results = {}
        for standard, rules in self.rules.items():
            required_fields = rules.get("required_fields", [])
            normalized_data = self.normalize_fields(sbom_data, sbom_format, required_fields)
            
            missing_fields = [field for field in required_fields if not normalized_data.get(field)]
            if missing_fields:
                results[standard] = {"status": "Fail", "missing_fields": missing_fields}
            else:
                results[standard] = {"status": "Pass"}
        
        return results
    
    def validate_xml(self, sbom_root):
        """Validate SBOM XML file against required fields using proper namespace handling"""
        results = {}

        # Extract actual namespace from XML (handle different CycloneDX versions)
        namespace = sbom_root.tag.split("}")[0].strip("{")
        ns = {"c": namespace}  # Dynamically extract namespace

        field_mappings = {
            "componentName": ".//c:metadata/c:component/c:name",
            "supplier": ".//c:metadata/c:tools/c:tool/c:vendor",
            "version": ".//c:metadata/c:component/c:version",
            "purl": ".//c:metadata/c:component/c:purl",
            "hashes": ".//c:components/c:component/c:hashes/c:hash",
            "license": ".//c:metadata/c:component/c:licenses/c:license/c:id",
            "vulnerabilityDisclosureURL": ".//c:metadata/c:tools/c:tool/c:name",
            "metadata": ".//c:metadata/c:timestamp"
        }

        for standard, rules in self.rules.items():
            required_fields = rules.get("required_fields", [])
            missing_fields = []
        
            for field in required_fields:
                xpath = field_mappings.get(field, None)
                if xpath and sbom_root.find(xpath, ns) is None:
                    missing_fields.append(field)
        
            if missing_fields:
                results[standard] = {"status": "Fail", "missing_fields": missing_fields}
            else:
                results[standard] = {"status": "Pass"}
    
        return results
