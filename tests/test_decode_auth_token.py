import unittest
import jwt

from src.lab_orchestrator_lib_auth.auth import decode_auth_token, LabInstanceTokenParams


class DecodeAuthTokenTestCase(unittest.TestCase):
    def test_normal_token_decoding(self):
        # define token that is expected to be generated.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6bnVsbH19.AprOiLu5PP38vawJ3il8gT3hu36VpOXIyjSbfO-_liU'

        expiry_time = 1633276902
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        # set a fixed secret key
        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7"

        # decodes the token using the method provided by this lib:
        decoded = decode_auth_token(token, secret_key)

        # check if all the fields are correct
        self.assertEqual(lab_id, decoded.lab_id)
        self.assertEqual(lab_instance_id, decoded.lab_instance_id)
        self.assertEqual(namespace_name, decoded.namespace_name)
        self.assertEqual(allowed_vmi_names, decoded.allowed_vmi_names)

    def test_expired_token_decoding(self):
        # define expired token and secret key which was used to generate it
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjoxLCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6bnVsbH19.7SKi38wV9T5BFRAo2BEw1ddUhcqsnt9XgGzBQVnLwFU'
        # set a fixed secret key
        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7"

        # checks if decode_auth_tokens raises an error about the expires signature
        self.assertRaises(
            jwt.exceptions.ExpiredSignatureError,
            decode_auth_token, token, secret_key
        )

    def test_asymmetric_token_decoding(self):
        # define token that is expected to be generated.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6bnVsbH19.JT59LeFYZTxQ5QA2CbNoMxUujWQ5iAuG01e6DE5dID_WxjCQtPi6VBt1sEy7wyeBHbXw3CoJaehH8_zGMsGmO4tbdMtEFJ_zhymCvZyFubhYPDUNZMhcFRFbdRH-v8eg_v2EvyJyB1-tG9LZWLDrBU439GYdC5lFyY0bln6ZtDTTm0dWcWakboQ6w9y7wEGyr-mpWt09Dv6YdzLvwPhDOJRleld-DfsSnOSZy8Y7J3hT3tmUpjmNxfWclYAeVrHSPiG37ECkc3ebMBnMAk6AKYsK4U6mDvSvd4xvEb_2ZBMkxMzYei171wEIaTkYMU7hAPtK-_NpzjI6cZAlBqQt8glnNDhbanKJfreNUEuTIXA9hr0kvhQORzZ81QXJC0Iug7IkQOsHnnWGq9FvrJvY6cULib4GbL_g_jc4tONDEj0LD4Of4uXFesn7PEvQN9OIT5k1ERUgQOU95EylqY-IrXbnoaTJ6IERiiI8_55lUszW4LHW5fc5dqLcO9Ij6hKKFBK6uyq4CVjdadpgwa-oOhJsGSw4ICo9ZRNMOOcWNmZjfB72HeGAbw4sbtDuXSPPvvoGxe7ftOxPrSUKNh9-L_qraFfl8z2FsN1PtLtC8oRiOhl6PvcpmbDJGppnVG5QCuo6q6woCngKFB-YFKyScN_5nbLbaDSY3FI6pKU6dW0'

        expiry_time = 1633276902
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        # set a fixed secret key
        with open("tests/jwtRS256.key.pub", "r") as f:
            public_key = f.read()

        # decodes the token using the method provided by this lib:
        decoded = decode_auth_token(token, public_key, algorithms=['RS256'])

        # check if all the fields are correct
        self.assertEqual(lab_id, decoded.lab_id)
        self.assertEqual(lab_instance_id, decoded.lab_instance_id)
        self.assertEqual(namespace_name, decoded.namespace_name)
        self.assertEqual(allowed_vmi_names, decoded.allowed_vmi_names)

    def test_additional_data(self):
        # define token that is expected to be generated.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il0sImFkZGl0aW9uYWxfZGF0YSI6eyJoYWxsbyI6IndlbHQifX19.zvrU9VIJmSto0sWKe65-UoWqwgWeOYIQal2XWPOxJW0'

        expiry_time = 1633276902
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5
        additional_data = {"hallo": "welt"}

        # set a fixed secret key
        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7"

        # decodes the token using the method provided by this lib:
        decoded = decode_auth_token(token, secret_key)

        # check if all the fields are correct
        self.assertEqual(lab_id, decoded.lab_id)
        self.assertEqual(lab_instance_id, decoded.lab_instance_id)
        self.assertEqual(namespace_name, decoded.namespace_name)
        self.assertEqual(allowed_vmi_names, decoded.allowed_vmi_names)
        self.assertDictEqual(additional_data, decoded.additional_data)

