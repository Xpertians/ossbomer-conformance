#!/bin/bash
rm -rf dist build ossa_scanner.egg-info
python3 setup.py sdist bdist_wheel > scripts/build.log
pip3 uninstall ossbomer-conformance > scripts/install.log
rm -rf /opt/homebrew/lib/python3.12/site-packages/ossbomer-conformance/ >> scripts/install.log
pip3 install dist/ossbomer_conformance-*.whl --force-reinstall >> scripts/install.log