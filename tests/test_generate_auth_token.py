import unittest
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from src.lab_orchestrator_lib_auth.auth import generate_auth_token, LabInstanceTokenParams


class GenerateAuthTokenTestCase(unittest.TestCase):
    def test_basic_token_generation(self):
        # define token that is expected to be generated.
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6bnVsbH19.AprOiLu5PP38vawJ3il8gT3hu36VpOXIyjSbfO-_liU'

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
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6bnVsbH19.JT59LeFYZTxQ5QA2CbNoMxUujWQ5iAuG01e6DE5dID_WxjCQtPi6VBt1sEy7wyeBHbXw3CoJaehH8_zGMsGmO4tbdMtEFJ_zhymCvZyFubhYPDUNZMhcFRFbdRH-v8eg_v2EvyJyB1-tG9LZWLDrBU439GYdC5lFyY0bln6ZtDTTm0dWcWakboQ6w9y7wEGyr-mpWt09Dv6YdzLvwPhDOJRleld-DfsSnOSZy8Y7J3hT3tmUpjmNxfWclYAeVrHSPiG37ECkc3ebMBnMAk6AKYsK4U6mDvSvd4xvEb_2ZBMkxMzYei171wEIaTkYMU7hAPtK-_NpzjI6cZAlBqQt8glnNDhbanKJfreNUEuTIXA9hr0kvhQORzZ81QXJC0Iug7IkQOsHnnWGq9FvrJvY6cULib4GbL_g_jc4tONDEj0LD4Of4uXFesn7PEvQN9OIT5k1ERUgQOU95EylqY-IrXbnoaTJ6IERiiI8_55lUszW4LHW5fc5dqLcO9Ij6hKKFBK6uyq4CVjdadpgwa-oOhJsGSw4ICo9ZRNMOOcWNmZjfB72HeGAbw4sbtDuXSPPvvoGxe7ftOxPrSUKNh9-L_qraFfl8z2FsN1PtLtC8oRiOhl6PvcpmbDJGppnVG5QCuo6q6woCngKFB-YFKyScN_5nbLbaDSY3FI6pKU6dW0'

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
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6bnVsbH19.Q0Dge-45EAcgJt2qlgZQEkq1ZCN__SCQdBeCWDkZzIc4gcodgeUUS4dxEq0towD1A_NL593glY5QJ1VLexqEmTHJVdCh0LhhcPiNAkgSuOhjcq2D50QRZClSMgaVsCv5OZ0CDp_AGgClfTHoOVTcGJvwJ7MOlrF_MI-OqWJxqnMrBbuvheZ3LXMDWosfbShtlHejR-Ri9UdsH7RlRaEAq-iSJevasb_cabbpTaHY0GYLqmzOF0k4ubAW7Bz0uHLuzHJ_nFJEXIh4Hd4CXLCBQAUF-jqfwIJRNqY7AN-CCipp171G7Y_eLflriHeUh9v93zIB1GQk0sWb0BhIvqcLKbXoo2WYwMlgrGEyc5lHYnPdCWABhkgi1d6JsGxP19GsmVEMz1wdoGN4zjvPs05DKoHfvKd9ciK97IQ6ieAZBHw4lpAeADi2c0o81tAreD7kGsnWEQavzgX1dfHa5jqeeqSdulyWNPaZ0kX6hlzhVmpUvbzAog3LlOqPEXjkjvOQmftwlpuZaj0jV68Nq5I32ZG49_3-6J0wIhTLkMOF5jkiHvuej660QYaisMHSej_UbhPLZtRW_4a2Qq0nm6iTMrqYzR_kH__z8hBs04pm9q3WvT4R0BiAfJxoo05TcV_3QeFZlsPeWg9pQxnAvvtEQJKotFAt-d4_D7hxmLvjvac'

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

    def test_additional_data(self):
        # define token that is expected to be generated.
        expected_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6eyJoYWxsbyI6IndlbHQifX19.zvrU9VIJmSto0sWKe65-UoWqwgWeOYIQal2XWPOxJW0'

        expiry_time = 8633272048
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5
        additional_data = {"hallo": "welt"}

        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7" # set a fixed secret key
        param = LabInstanceTokenParams(lab_id, lab_instance_id, namespace_name, allowed_vmi_names, additional_data=additional_data) # create test parameters for token
        generated_token = generate_auth_token(user_id, param, secret_key, expires_at=expiry_time) # generate a token with fixed expiry date for reproduction

        self.assertEqual(expected_token, generated_token)

        decoded = jwt.decode(generated_token, key=secret_key, algorithms=['HS256'])

        self.assertEqual(expiry_time, decoded["exp"])
        self.assertEqual(lab_id, decoded["lab_instance"]["lab_id"])
        self.assertEqual(lab_instance_id, decoded["lab_instance"]["lab_instance_id"])
        self.assertEqual(namespace_name, decoded["lab_instance"]["namespace_name"])
        self.assertEqual(allowed_vmi_names, decoded["lab_instance"]["allowed_vmi_names"])
        self.assertEqual(user_id, decoded["id"])
        self.assertDictEqual(additional_data, decoded["lab_instance"]["additional_data"])

