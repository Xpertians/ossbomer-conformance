# ossbomer-conformance

**ossbomer-conformance** is a Python library and CLI tool that validates SBOM (Software Bill of Materials) files against NTIA, CRA, and other regulatory conformance rules. It supports **SPDX** and **CycloneDX** formats in JSON and XML.

## Features
- Validates SBOMs against **NTIA and CRA** requirements.
- Supports **SPDX and CycloneDX** formats (JSON & XML).
- Detects missing fields and structural inconsistencies (WIP).


## Installation

```
pip install ossbomer-conformance
```

## Usage
CLI Usage to Validate an SBOM file:

```
ossbomer-conformance --file sbom.json
```

Specify a custom rules file:

```
ossbomer-conformance --file sbom.json --rules custom_rules.json
```

Library Integration:

```
from ossbomer_conformance.validator import SBOMConformanceValidator

validator = SBOMConformanceValidator("config.json")
result = validator.validate_sbom("sbom.json")
print(result)
```


### License
This project is licensed under the MIT License.