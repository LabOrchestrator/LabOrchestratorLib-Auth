from lab_orchestrator_lib_auth import auth
import os

secret_key = os.environ["SECRET_KEY"]
param = auth.LabInstanceTokenParams(1, 9, "pentest-ubuntu-3-9", ["ubuntu"])
print(param)
print(auth.generate_auth_token(5, param, secret_key))
