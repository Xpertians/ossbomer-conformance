import json
import click
import os
import pkg_resources
from ossbomer_conformance.validator import SBOMConformanceValidator

DEFAULT_CONFIG_FILE = pkg_resources.resource_filename("ossbomer_conformance", "config.json")

@click.command()
@click.option("--file", "sbom_file", required=True, help="Path to SBOM file (JSON or XML)")
@click.option("--rules", "rules_file", default=None, help="Path to custom rules file (JSON format)")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
def validate(sbom_file, rules_file, json_output):
    if rules_file is None:
        rules_file = DEFAULT_CONFIG_FILE
        if not os.path.exists(rules_file):
            click.echo(f"Error: Default config file '{DEFAULT_CONFIG_FILE}' not found in package. Please provide a valid rules file.", err=True)
            exit(1)

    try:
        validator = SBOMConformanceValidator(rules_file)
        result = validator.validate_sbom(sbom_file)

        if "error" in result:
            click.echo(f"Error: {result['error']}", err=True)
            exit(1)

        if json_output:
            click.echo(json.dumps(result, indent=4))
        else:
            for standard, details in result.items():
                click.echo(f"{standard}: {details['status']}")
                if details["status"] == "Fail":
                    click.echo(f"  Missing fields: {', '.join(details['missing_fields'])}")

    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        exit(1)

if __name__ == "__main__":
    validate()
