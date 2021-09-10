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
    vmi_name: str


def generate_auth_token(user_id: Identifier, lab_instance_token_params: LabInstanceTokenParams,
                        secret_key: str, expires_in: int = 600) -> str:
    return jwt.encode({
        'id': user_id,
        'exp': time.time() + expires_in,
        'lab_instance': {
            'lab_id': lab_instance_token_params.lab_id,
            'lab_instance_id': lab_instance_token_params.lab_instance_id,
            'namespace_name': lab_instance_token_params.namespace_name,
            'vmi_name': lab_instance_token_params.vmi_name
        }}, secret_key, algorithm='HS256')


def verify_auth_token(token, user_id: Identifier, lab_id: Identifier,
                      secret_key: str) -> Optional[LabInstanceTokenParams]:
    try:
        data = jwt.decode(token, secret_key, algorithms=['HS256'])
    except:
        return None
    if lab_id == data['lab_instance']['lab_id'] and user_id == data['user_id']:
        return LabInstanceTokenParams(
            lab_id=data['lab_instance']['lab_id'],
            lab_instance_id=data['lab_instance']['lab_instance_id'],
            namespace_name=data['lab_instance']['namespace_name'],
            vmi_name=data['lab_instance']['vmi_name']
        )
    return None
