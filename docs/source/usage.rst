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

Test autofunction 1:

.. autofunction:: lab_orchestrator_lib_auth.auth.generate_auth_token

To create a JWT token you can use the ``auth.generate_auth_token(...)`` function:

.. autofunction:: auth.generate_auth_token

The ``user_id`` parameter should be either of type ``str`` or ``int`` and contain the id of the user. As decryption HS256 is used, which is a symmetric algorithm. The ``secret_key`` parameter contains the symmetric key that is used to encrypt and decrypt the token. The ``lab_instance_token_params`` parameter contains the information that are written into the token:

.. autoclass:: auth.LabInstanceTokenParams

The ``lab_id`` parameter is the id of the lab this token is generated for. The ``lab_instance_id`` is the id of the lab instance this token is generated for. The ``namespace_name`` parameter needs to contain the namespace the VMs are running into. The ``allowed_vmi_names`` parameter is a list of the VM-names the user is allowed to access. So you can use one token for accessing multiple VMs in a lab.

For example:

>>> import auth
>>> param = auth.LabInstanceTokenParams(1, 9, "pentest-ubuntu-3-9", ["ubuntu"])
>>> auth.generate_auth_token(5, param, "secret")
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiZXhwIjoxNjMyMTM3OTExLjc5NTg1NjcsImxhYl9pbnN0YW5jZSI6eyJsYWJfaWQiOjEsImxhYl9pbnN0YW5jZV9pZCI6OSwibmFtZXNwYWNlX25hbWUiOiJwZW50ZXN0LXVidW50dS0zLTkiLCJhbGxvd2VkX3ZtaV9uYW1lcyI6WyJ1YnVudHUiXX19.ag6f2OsBP5FFyDN9kEw_ivesT8Pa0jGMp2eKjRM9iCs'

