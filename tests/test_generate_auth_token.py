import unittest
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from src.lab_orchestrator_lib_auth.auth import generate_auth_token, LabInstanceTokenParams


class GenerateAuthTokenTestCase(unittest.TestCase):
    def test_basic_token_generation(self):
        # define token that is expected to be generated.
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.dRmdjiuKdFeyu2HHJWJQVspW1Aw1rMB6dJQe7LoLZww'

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

    def test_asymmetric_token_generation(self):
        # define token that is expected to be generated.
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.Z9foeGq9hk4sdCLzWCUdgq6qz_mX2YfWgSzxyJyGY-8q4Zv48GRdvw96SM1RlUaBu_gaRX6mXF-n6lBzXQx65KAyhuktPZF0gPpGuMQEUXe-J1n-YO5qKq7QJ-5_XLAxkiFBNnzWO4x4jbppVPFdfTKamB43YwNCbppF9dUNGkOR1Xsbo1EQ4ihr705EKBMVUObVWZmfF1AWrSiVXVKxJkw-WrHu9QQWgTKY75ai5u0O3yDrJOoMJ0n0ItFOWXSFVtphTicFff-pKz5DNIpipq0N7lUOtYqtRB21qV7lyYW8oJE7iaQLnARwKTo3eX-7Fy2_viDYk0woxKzb9mtBIg3mIFfU6S1sgHHjDgt18ciuzKq2wFqYA2a09liFJkSLYo9qP9EtkH0cPo2rTDcRShJ5fJa67UDZ5HsnLql78TR3X0i3qs_p7E0UaqE23dGCLPHPNPeILWKXqKduuBpz8_v-2ajDH4t-bt543ZYpX-sZF-lYHbYrwWANon_HCzcRRupMMmvxxKXOEl8RP4s0Bk5g9_oajuH4Tbr3TiHbqdI3xayCkPC4vgXCNVSg6gsUQLeurNsbGfzgfkIAGOeEl9rxWuDDpGi6YQcXlq4Mr-gyj61HzMkoNMbi93hqo-sT1-K2_sq6ZiWZ2fGaWVcNsvt8fBu5mTfNI10ZuaX-G_k'

        expiry_time = 8633272048
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        # created keys with this: https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9
        with open("tests/jwtRS256.key", "r") as f:
            private_key = f.read()
        with open("tests/jwtRS256.key.pub", "r") as f:
            public_key = f.read()
        param = LabInstanceTokenParams(lab_id, lab_instance_id, namespace_name, allowed_vmi_names) # create test parameters for token
        generated_token = generate_auth_token(user_id, param, private_key, expires_at=expiry_time, algorithm="RS256") # generate a token with fixed expiry date for reproduction
        self.assertEqual(expected_token, generated_token)

        decoded = jwt.decode(generated_token, key=public_key, algorithms=['RS256'])

        self.assertEqual(expiry_time, decoded["exp"])
        self.assertEqual(lab_id, decoded["lab_instance"]["lab_id"])
        self.assertEqual(lab_instance_id, decoded["lab_instance"]["lab_instance_id"])
        self.assertEqual(namespace_name, decoded["lab_instance"]["namespace_name"])
        self.assertEqual(allowed_vmi_names, decoded["lab_instance"]["allowed_vmi_names"])
        self.assertEqual(user_id, decoded["id"])

    def test_asymmetric_pwd_token_generation(self):
        """Tests the token creation with a key that is protected by a password."""
        # define token that is expected to be generated.
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.JOUxV7dOKbSPFheDtL1WId2QSmEfsxZBwH5fLUmFMgPY3fYeTRHjv09NTpFfGQ9ze9CNFwimq_k7Zple0hhudzFHSw-_zaIvlJsHGz3oWCFSGdS03uiEi-OtNVGS2UwAA0vbw8IZYcpMwlXJfTa_YIs5qtuG-AWexQ5BfXp2pNC-U_9TBM40H4nEQ81NmPaLhI1XjVwPt2nsZdsHJImC2UGBCr2AoxUtCTysfvxRFr9S2G9kcNDaMmfvK9vV63sfk7b2mmpAURkwHH-YgszILqSq-Rkv-HiZWVaAA6yahKob7ih_o2pWbcR-OE-75w_Ej6I5LVfb16QsWugTnvgizvwXIHlh-QGQ92OpIO_W15y3uNRodTSudWSvw9BoSwvgZ2WLkvXn9xOHGVjAGFMasQhzinNx17TcjRSqD1Z7GnOpRSyeq5W4TLvYhgZgc_THeaxIMXec4AnKE9g1XwAz9XxfOgUEZd8RpjhlZPYC_VUnXTENOytWVOwvvUd_W8zUV5gQNcc-E1_DhQUtvLX8eRfgopRwK869JR5ekmzD0yAegKcLEuawDAQKFWfQkf0ejHUEM7X068sLPeSxpvge2z8taHpOx5VzVLEIGnm0OOvooCK-frkchpOrtMJO8Bwl1JOSTsVwQ_0yWWPa1y85W8RQGL1TaDG0oFAGN0P_Xq4'

        expiry_time = 8633272048
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        # created keys with this: https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9
        with open("tests/jwtRS256-pwd.key", "rb") as f:
            passphrase = b"secret"
            pem_bytes = f.read()
        private_key = serialization.load_pem_private_key(
            pem_bytes, password=passphrase, backend=default_backend()
        )
        with open("tests/jwtRS256-pwd.key.pub", "r") as f:
            public_key = f.read()
        param = LabInstanceTokenParams(lab_id, lab_instance_id, namespace_name, allowed_vmi_names) # create test parameters for token
        generated_token = generate_auth_token(user_id, param, private_key, expires_at=expiry_time, algorithm="RS256") # generate a token with fixed expiry date for reproduction
        self.assertEqual(expected_token, generated_token)

        decoded = jwt.decode(generated_token, key=public_key, algorithms=['RS256'])

        self.assertEqual(expiry_time, decoded["exp"])
        self.assertEqual(lab_id, decoded["lab_instance"]["lab_id"])
        self.assertEqual(lab_instance_id, decoded["lab_instance"]["lab_instance_id"])
        self.assertEqual(namespace_name, decoded["lab_instance"]["namespace_name"])
        self.assertEqual(allowed_vmi_names, decoded["lab_instance"]["allowed_vmi_names"])
        self.assertEqual(user_id, decoded["id"])

