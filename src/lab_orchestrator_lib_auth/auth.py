"""Authentication Module of LabOrchestrator.

This module contains the authentication methods that are used by the LabOrchestrator.
"""
from dataclasses import dataclass
from typing import Optional, Union, List

import jwt
import time


Identifier = Union[str, int]


@dataclass
class LabInstanceTokenParams:
    """Data that is inserted into the JWT token.

    :param lab_id: The id of the lab.
    :param lab_instance_id: The id of the lab instance.
    :param namespace_name: Name of the namespace the VMs are running into.
    :param allowed_vmi_names: List of VM-names that the user is allowed to access.
    """
    lab_id: Identifier
    lab_instance_id: Identifier
    namespace_name: str
    allowed_vmi_names: List[str]


def generate_auth_token(user_id: Identifier, lab_instance_token_params: LabInstanceTokenParams,
                        secret_key: str, expires_in: int = 600) -> str:
    """Generates a JWT token.

    :param user_id: Id of the user.
    :param lab_instance_token_params: The data that is included in the token.
    :param secret_key: The secret key that is used to decrypt the token.
    :param expires_in: Amount of seconds the token is valid.
    :return: A JWT token.
    """
    return jwt.encode({
        'id': user_id,
        'exp': time.time() + expires_in,
        'lab_instance': {
            'lab_id': lab_instance_token_params.lab_id,
            'lab_instance_id': lab_instance_token_params.lab_instance_id,
            'namespace_name': lab_instance_token_params.namespace_name,
            'allowed_vmi_names': lab_instance_token_params.allowed_vmi_names
        }}, secret_key, algorithm='HS256')


def decode_auth_token(token: str, secret_key: str) -> Optional[LabInstanceTokenParams]:
    """Decodes a JWT token.

    :param token: The token to decode.
    :param secret_key: Key that should be used to decrypt the token.
    :return: The data that is contained in the token or None if decode goes wrong.
    """
    try:
        data = jwt.decode(token, secret_key, algorithms=['HS256'])
        return LabInstanceTokenParams(
            lab_id=data['lab_instance']['lab_id'],
            lab_instance_id=data['lab_instance']['lab_instance_id'],
            namespace_name=data['lab_instance']['namespace_name'],
            allowed_vmi_names=data['lab_instance']['allowed_vmi_names']
        )
    except:
        return None


def verify_auth_token(token: str, vmi_name: str, secret_key: str) -> Optional[LabInstanceTokenParams]:
    """Decodes a token and verifies if it's valid.

    Checks if the vmi_name is allowed in the token.

    :param token: The token to decode and verify.
    :param vmi_name: The vmi_name the user wants to use.
    :param secret_key: Key that is used to decrypt the token.
    :return: The data that is contained in the token or None if the the token or vmi name was invalid or not allowed.
    """
    data = decode_auth_token(token, secret_key)
    if data is None or vmi_name not in data.allowed_vmi_names:
        return None
    return data
