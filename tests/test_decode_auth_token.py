import unittest
import jwt

from src.lab_orchestrator_lib_auth.auth import decode_auth_token, LabInstanceTokenParams


class DecodeAuthTokenTestCase(unittest.TestCase):
    def test_normal_token_decoding(self):
        # define token that is expected to be generated.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.dRmdjiuKdFeyu2HHJWJQVspW1Aw1rMB6dJQe7LoLZww'

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
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjoxNjMzMjc2OTAyLCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.b5JkPt1er-9ZkYpPxqRTy2d6w9qzD4I29UIcurxePz0'
        # set a fixed secret key
        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7"

        # checks if decode_auth_tokens raises an error about the expires signature
        self.assertRaises(
            jwt.exceptions.ExpiredSignatureError,
            decode_auth_token, token, secret_key
        )

    def test_asymmetric_token_decoding(self):
        # define token that is expected to be generated.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.Z9foeGq9hk4sdCLzWCUdgq6qz_mX2YfWgSzxyJyGY-8q4Zv48GRdvw96SM1RlUaBu_gaRX6mXF-n6lBzXQx65KAyhuktPZF0gPpGuMQEUXe-J1n-YO5qKq7QJ-5_XLAxkiFBNnzWO4x4jbppVPFdfTKamB43YwNCbppF9dUNGkOR1Xsbo1EQ4ihr705EKBMVUObVWZmfF1AWrSiVXVKxJkw-WrHu9QQWgTKY75ai5u0O3yDrJOoMJ0n0ItFOWXSFVtphTicFff-pKz5DNIpipq0N7lUOtYqtRB21qV7lyYW8oJE7iaQLnARwKTo3eX-7Fy2_viDYk0woxKzb9mtBIg3mIFfU6S1sgHHjDgt18ciuzKq2wFqYA2a09liFJkSLYo9qP9EtkH0cPo2rTDcRShJ5fJa67UDZ5HsnLql78TR3X0i3qs_p7E0UaqE23dGCLPHPNPeILWKXqKduuBpz8_v-2ajDH4t-bt543ZYpX-sZF-lYHbYrwWANon_HCzcRRupMMmvxxKXOEl8RP4s0Bk5g9_oajuH4Tbr3TiHbqdI3xayCkPC4vgXCNVSg6gsUQLeurNsbGfzgfkIAGOeEl9rxWuDDpGi6YQcXlq4Mr-gyj61HzMkoNMbi93hqo-sT1-K2_sq6ZiWZ2fGaWVcNsvt8fBu5mTfNI10ZuaX-G_k'

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

