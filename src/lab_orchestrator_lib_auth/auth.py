from dataclasses import dataclass
from typing import Optional, Union, List

import jwt
import time


Identifier = Union[str, int]


@dataclass
class LabInstanceTokenParams:
    lab_id: Identifier
    lab_instance_id: Identifier
    namespace_name: str
    allowed_vmi_names: List[str]


def generate_auth_token(user_id: Identifier, lab_instance_token_params: LabInstanceTokenParams,
                        secret_key: str, expires_in: int = 600) -> str:
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
    data = decode_auth_token(token, secret_key)
    if data is None or vmi_name not in data.allowed_vmi_names:
        return None
    return data
