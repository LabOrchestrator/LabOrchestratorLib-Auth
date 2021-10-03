import unittest
import jwt

from src.lab_orchestrator_lib_auth.auth import generate_auth_token, LabInstanceTokenParams


class GenerateAuthTokenTestCase(unittest.TestCase):
    def test_basic_token_generation(self):
        # define token that is expected to be generated.
        expected_token = b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.dRmdjiuKdFeyu2HHJWJQVspW1Aw1rMB6dJQe7LoLZww'

        expiry_time = 8633272048
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7" # set a fixed secret key
        param = LabInstanceTokenParams(lab_id, lab_instance_id, namespace_name, allowed_vmi_names) # create test parameters for token
        generated_token = generate_auth_token(user_id, param, secret_key, expires_at=expiry_time) # generate a token with fixed expiry date for reproduction

        self.assertEqual(expected_token, generated_token)

        decoded = jwt.decode(generated_token, key=secret_key, algorithms=['HS256'])

        self.assertEqual(expiry_time, decoded["exp"])
        self.assertEqual(lab_id, decoded["lab_instance"]["lab_id"])
        self.assertEqual(lab_instance_id, decoded["lab_instance"]["lab_instance_id"])
        self.assertEqual(namespace_name, decoded["lab_instance"]["namespace_name"])
        self.assertEqual(allowed_vmi_names, decoded["lab_instance"]["allowed_vmi_names"])
        self.assertEqual(user_id, decoded["id"])

