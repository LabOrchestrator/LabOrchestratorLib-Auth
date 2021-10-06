Usage
=====

.. _installation:

Installation
------------

To use LabOrchestratorLib-Auth, first install it using pip:

.. code-block:: console

   (.venv) $ pip3 install lab-orchestrator-lib-auth

Creating Tokens
----------------

To create a JWT token you can use the ``lab_orchestrator_lib_auth.auth.generate_auth_token(...)`` function:

.. autofunction:: lab_orchestrator_lib_auth.auth.generate_auth_token

The ``user_id`` parameter should be either of type ``str`` or ``int`` and contain the id of the user. As decryption HS256 is used, which is a symmetric algorithm. The ``secret_key`` parameter contains the symmetric key that is used to encrypt and decrypt the token. The ``lab_instance_token_params`` parameter contains the information that are written into the token:

.. autoclass:: lab_orchestrator_lib_auth.auth.LabInstanceTokenParams

The ``allowed_vmi_names`` parameter is a list of the VM-names the user is allowed to access. So you can use one token for accessing multiple VMs in a lab.

For example:

>>> import lab_orchestrator_lib_auth.auth
>>> param = lab_orchestrator_lib_auth.auth.LabInstanceTokenParams(1, 9, "pentest-ubuntu-3-9", ["ubuntu"])
>>> lab_orchestrator_lib_auth.auth.generate_auth_token(5, param, "secret")
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjoxNjMyMTM3OTExLjc5NTg1NjcsImxhYl9pbnN0YW5jZSI6eyJsYWJfaWQiOjEsImxhYl9pbnN0YW5jZV9pZCI6OSwibmFtZXNwYWNlX25hbWUiOiJwZW50ZXN0LXVidW50dS0zLTkiLCJhbGxvd2VkX3ZtaV9uYW1lcyI6WyJ1YnVudHUiXX19.ag6f2OsBP5FFyDN9kEw_ivesT8Pa0jGMp2eKjRM9iCs'

To create tokens with asymmetric keys install ``pyjwt[crypto]`` and take a look at these two links:

* `https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa <https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa>`_
* `https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9 <https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9>`_

Decoding Tokens
---------------

To decode a JWT token you can use the ``lab_orchestrator_lib_auth.auth.decode_auth_token(...)`` function:

.. autofunction:: lab_orchestrator_lib_auth.auth.decode_auth_token

This function also uses HS256 as decryption algorithm so you need to have the same secret key as during the creation of a token. This method then returns the data that was inserted into the token.

Verifying Tokens
----------------

To verfiy a JWT token you can use the ``lab_orchestrator_lib_auth.auth.verify_auth_token(...)`` function:

.. autofunction:: lab_orchestrator_lib_auth.auth.verify_auth_token

This function checks if the given ``vmi_name`` is allowed in the token.
