import re
from setuptools import setup, find_packages
from os.path import abspath, dirname, join

CURDIR = dirname(abspath(__file__))

with open(join(CURDIR, 'src', 'lab_orchestrator_lib_auth', '__init__.py'), "r", encoding="utf-8") as f:
    VERSION = re.search('^__version__ = "(.*)"', f.read()).group(1)
with open(join(CURDIR, 'README.md'), "r", encoding="utf-8") as f:
    LONG_DESCRIPTION = f.read()
with open(join(CURDIR, 'requirements.txt'), "r", encoding="utf-8") as f:
    REQUIREMENTS = f.read().splitlines()

setup(
    name="lab-orchestrator-lib-auth",
    version=VERSION,
    author="Marco Schlicht",
    author_email="git@privacymail.dev",
    description="Authentication module for lab-orchestrator-lib.",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/LabOrchestrator/LabOrchestratorLib-Auth",
    license="Mozilla Public License 2.0 (MPL 2.0)",
    project_urls={
        "Bug Tracker": "https://github.com/LabOrchestrator/LabOrchestratorLib-Auth/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=REQUIREMENTS,
)
