import json
import xml.etree.ElementTree as ET

class SBOMConformanceValidator:
    def __init__(self, rules_file="config.json"):
        self.rules = self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        try:
            with open(rules_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError("Error: Invalid or missing rules file. Please provide a valid configuration file.")
    
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
        results = {}
        for standard, rules in self.rules.items():
            missing_fields = [field for field in rules.get("required_fields", []) if field not in sbom_data]
            if missing_fields:
                results[standard] = {"status": "Fail", "missing_fields": missing_fields}
            else:
                results[standard] = {"status": "Pass"}
        return results
    
    def validate_xml(self, sbom_root):
        results = {}
        for standard, rules in self.rules.items():
            missing_fields = [field for field in rules.get("required_fields", []) if sbom_root.find(field) is None]
            if missing_fields:
                results[standard] = {"status": "Fail", "missing_fields": missing_fields}
            else:
                results[standard] = {"status": "Pass"}
        return results
