[![Status](https://img.shields.io/pypi/status/lab-orchestrator-lib-auth)](https://pypi.org/project/lab-orchestrator-lib-auth/)
[![Version](https://img.shields.io/pypi/v/lab-orchestrator-lib-auth?label=release)](https://pypi.org/project/lab-orchestrator-lib-auth/)
[![License](https://img.shields.io/github/license/laborchestrator/laborchestratorlib-auth)](https://github.com/LabOrchestrator/LabOrchestratorLib-Auth/blob/main/LICENSE)
[![Issues](https://img.shields.io/github/issues/laborchestrator/laborchestratorlib-auth)](https://github.com/laborchestrator/laborchestratorlib-auth/issues)
[![Downloads](https://img.shields.io/pypi/dw/lab-orchestrator-lib-auth)](https://pypi.org/project/lab-orchestrator-lib-auth/)
[![Dependencies](https://img.shields.io/librariesio/release/pypi/lab-orchestrator-lib-auth)](https://libraries.io/pypi/lab-orchestrator-lib-auth)
[![Docs](https://img.shields.io/readthedocs/laborchestratorlib-auth)](https://laborchestratorlib-auth.readthedocs.io/en/latest/)


# Lab Orchestrator Lib Auth

This package contains the lab orchestrator library authentication module.

[Github](https://github.com/LabOrchestrator/LabOrchestratorLib-Auth)  
[PyPi](https://pypi.org/project/lab-orchestrator-lib-auth/)  
[Read The Docs](https://laborchestratorlib-auth.readthedocs.io/en/latest/index.html)

## Installation

- `pip3 install lab-orchestrator-lib-auth`

## Documentation

Check out the developer documentation at [laborchestratorlib-auth.readthedocs.io](https://laborchestratorlib-auth.readthedocs.io/en/latest/index.html).

## Usage

The library contains one module called auth that contains 3 methods and one dataclass.

The first method `generate_auth_token` is used to generate a JWT token. The token contains the user id, and some information about the lab instance for which this token is created. That also contains a list of `vmi_names` the user should be allowed to connect to. `HS256` is used as algorithm which is a symmetric algorithm, so you need to use the same secret for both: encryption and decryption of the key.

The next method `decode_auth_token` decodes the previously encoded JWT token. It returns the information that is contained in the token.

The third method `verify_auth_token` contains the parameter `vmi_name` and checks if this `vmi_name` is allowed. If it's not allowed the method will return none.

See more at: [laborchestratorlib-auth.readthedocs.io](https://laborchestratorlib-auth.readthedocs.io/en/latest/index.html).

## Examples

There is one example that shows how to create a token with the library. For other examples you need to look into the [LabOrchestratorLib](https://github.com/LabOrchestrator/LabOrchestratorLib) or [WebsocketProxy](https://github.com/LabOrchestrator/WebsocketProxy).

## Contributing

### Issues

Feel free to open [issues](https://github.com/LabOrchestrator/LabOrchestratorLib-Auth/issues).

### Project Structure

The `src` folder contains the source code of the library. The `tests` folder contains the test cases. `examples` contains some example scripts of how to use the library. There is a makefile that contains some shortcuts for example to run the test cases and to make a release. Run `make help` to see all targets. The `docs` folder contains rst docs that are used in [read the docs](https://laborchestratorlib-auth.readthedocs.io/en/latest/).

### Developer Dependencies

- Python 3.8
- Make
- `pip install -r requirements.txt`
- `pip install -r requirements-dev.txt`

### Releases

Your part:

1. Create branch for your feature (`issue/ISSUE_ID-SHORT_DESCRIPTION`)
2. Code
3. Make sure test cases are running and add new ones for your feature
4. Create MR into master
5. Increase version number in `src/lab_orchestrator_lib_auth/__init__.py` (semantic versioning)

Admin part:

1. Check and accept MR
2. Merge MR
3. Run `make release`

### Docs

To generate the docs run: `cd docs && make html`.
