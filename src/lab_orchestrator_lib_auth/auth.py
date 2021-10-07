"""Authentication Module of LabOrchestrator.

This module contains the authentication methods that are used by the LabOrchestrator.
"""
from dataclasses import dataclass
from typing import Optional, Tuple, Union, List

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
                        secret_key: str, expires_in: int = 60 * 60,
                        expires_at: Optional[int] = None,
                        algorithm: str = 'HS256'
                        ) -> str:
    """Generates a JWT token.

    :param user_id: Id of the user.
    :param lab_instance_token_params: The data that is included in the token.
    :param secret_key: The secret key that is used to decrypt the token.
    :param expires_in: Amount of seconds the token is valid.
    :param expires_at: Optional UNIX time at which this token expires. Overwrites expires_in.
    :param algorithm: Algorithm that should be used for creating the token. Available algorithms: https://pyjwt.readthedocs.io/en/latest/algorithms.html
    :return: A JWT token.
    """
    if not expires_at:
        expires_at = time.time() + expires_in

    return jwt.encode({
        'id': user_id,
        'exp': expires_at,
        'lab_instance': {
            'lab_id': lab_instance_token_params.lab_id,
            'lab_instance_id': lab_instance_token_params.lab_instance_id,
            'namespace_name': lab_instance_token_params.namespace_name,
            'allowed_vmi_names': lab_instance_token_params.allowed_vmi_names
        }}, secret_key, algorithm=algorithm)


def decode_auth_token(token: str, secret_key: str, algorithms: Optional[List[str]] = None) -> LabInstanceTokenParams:
    """Decodes a JWT token.

    :param token: The token to decode.
    :param secret_key: Key that should be used to decrypt the token.
    :param algorithms: Allowed algorithms. If None, ['HS256'] is used.
    :return: The data that is contained in the token or None if decode goes wrong.
    :raise jwt.exceptions.DecodeError: Raised when a token cannot be decoded because it failed validation.
    :raise jwt.exceptions.InvalidSignatureError: Raised when a token’s signature doesn’t match the one provided as part of the token.
    :raise jwt.exceptions.ExpiredSignatureError: Raised when a token’s exp claim indicates that it has expired.
    :raise jwt.exceptions.InvalidAudienceError: Raised when a token’s aud claim does not match one of the expected audience values.
    :raise jwt.exceptions.InvalidIssuerError: Raised when a token’s iss claim does not match the expected issuer.
    :raise jwt.exceptions.InvalidIssuedAtError: Raised when a token’s iat claim is in the future.
    :raise jwt.exceptions.ImmatureSignatureError: Raised when a token’s nbf claim represents a time in the future.
    :raise jwt.exceptions.InvalidKeyError: Raised when the specified key is not in the proper format.
    :raise jwt.exceptions.InvalidAlgorithmError: Raised when the specified algorithm is not recognized by PyJWT.
    :raise jwt.exceptions.MissingRequiredClaimError: Raised when a claim that is required to be present is not contained in the claimset.
    """
    if algorithms is None:
        algorithms = ['HS256']
    data = jwt.decode(token, secret_key, algorithms=algorithms)
    return LabInstanceTokenParams(
        lab_id=data['lab_instance']['lab_id'],
        lab_instance_id=data['lab_instance']['lab_instance_id'],
        namespace_name=data['lab_instance']['namespace_name'],
        allowed_vmi_names=data['lab_instance']['allowed_vmi_names']
    )


def verify_auth_token(token: str, vmi_name: str, secret_key: str, algorithms: Optional[List[str]] = None) -> Tuple[bool, LabInstanceTokenParams]:
    """Decodes a token and verifies if it's valid.

    Checks if the vmi_name is allowed in the token.

    :param token: The token to decode and verify.
    :param vmi_name: The vmi_name the user wants to use.
    :param secret_key: Key that is used to decrypt the token.
    :return: The result of the verification as a boolean and the data contained in the token.
    :raise jwt.exceptions.DecodeError: Raised when a token cannot be decoded because it failed validation.
    :raise jwt.exceptions.InvalidSignatureError: Raised when a token’s signature doesn’t match the one provided as part of the token.
    :raise jwt.exceptions.ExpiredSignatureError: Raised when a token’s exp claim indicates that it has expired.
    :raise jwt.exceptions.InvalidAudienceError: Raised when a token’s aud claim does not match one of the expected audience values.
    :raise jwt.exceptions.InvalidIssuerError: Raised when a token’s iss claim does not match the expected issuer.
    :raise jwt.exceptions.InvalidIssuedAtError: Raised when a token’s iat claim is in the future.
    :raise jwt.exceptions.ImmatureSignatureError: Raised when a token’s nbf claim represents a time in the future.
    :raise jwt.exceptions.InvalidKeyError: Raised when the specified key is not in the proper format.
    :raise jwt.exceptions.InvalidAlgorithmError: Raised when the specified algorithm is not recognized by PyJWT.
    :raise jwt.exceptions.MissingRequiredClaimError: Raised when a claim that is required to be present is not contained in the claimset.
    """

    data = decode_auth_token(token, secret_key, algorithms=algorithms)
    is_forbidden = vmi_name not in data.allowed_vmi_names

    return not is_forbidden, data
