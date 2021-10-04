import unittest
import jwt

from src.lab_orchestrator_lib_auth.auth import verify_auth_token, LabInstanceTokenParams


class VerifyAuthTokenTestCase(unittest.TestCase):
    def test_allowed_token_verification(self):
        # define token that allows access to vmi specified below.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.dRmdjiuKdFeyu2HHJWJQVspW1Aw1rMB6dJQe7LoLZww'
        vmi_name = "ubuntu"

        expiry_time = 1633276902
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        # set a fixed secret key
        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7"

        # decodes the token using the method provided by this lib:
        verify_result, verify_result_data = verify_auth_token(token, vmi_name, secret_key)

        # verify that token is allowed for vmi
        self.assertTrue(verify_result)

        # check if all the fields are correct
        self.assertEqual(lab_id, verify_result_data.lab_id)
        self.assertEqual(lab_instance_id, verify_result_data.lab_instance_id)
        self.assertEqual(namespace_name, verify_result_data.namespace_name)
        self.assertEqual(allowed_vmi_names, verify_result_data.allowed_vmi_names)
    
    def test_forbidden_token_verification(self):
        # define token which does not allow access to the vmi specified below.
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjo4NjMzMjcyMDQ4LCJsYWJfaW5zdGFuY2UiOnsibGFiX2lkIjoxLCJsYWJfaW5zdGFuY2VfaWQiOjksIm5hbWVzcGFjZV9uYW1lIjoicGVudGVzdC11YnVudHUtMy05IiwiYWxsb3dlZF92bWlfbmFtZXMiOlsidWJ1bnR1Il19fQ.dRmdjiuKdFeyu2HHJWJQVspW1Aw1rMB6dJQe7LoLZww'
        vmi_name = "manjaro"

        expiry_time = 1633276902
        lab_id = 1
        lab_instance_id = 9
        namespace_name = "pentest-ubuntu-3-9"
        allowed_vmi_names = ["ubuntu"]
        user_id = 5

        # set a fixed secret key
        secret_key = "8560e6637120e49406a631ed91d2302bc280474f26860920f1249d6f213c78b7"

        # decodes the token using the method provided by this lib:
        verify_result, verify_result_data = verify_auth_token(token, vmi_name, secret_key)

        # verify that token is allowed for vmi
        self.assertFalse(verify_result)

        # check if all the fields are correct
        self.assertEqual(lab_id, verify_result_data.lab_id)
        self.assertEqual(lab_instance_id, verify_result_data.lab_instance_id)
        self.assertEqual(namespace_name, verify_result_data.namespace_name)
        self.assertEqual(allowed_vmi_names, verify_result_data.allowed_vmi_names)

