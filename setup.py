from setuptools import setup, find_packages

setup(
    name="ossbomer-conformance",
    version="1.2.0",
    author="Oscar Valenzuela",
    author_email="oscar.valenzuela.b@gmail.com",
    description="OSSBOMER - SBOM Conformance against NTIA, CRA, and other compliance requirements.",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0",
        "jsonschema>=4.0",
    ],
    entry_points={
        "console_scripts": [
            "ossbomer-conformance=ossbomer_conformance.cli:validate"
        ]
    },
    package_data={  
        "ossbomer_conformance": ["config.json"],
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.7",
)
