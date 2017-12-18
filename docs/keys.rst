.. _master-keys:

Master keys
===========

**IMPORTANT**: To decrypt and encrypt Amiibo data, you will need two master keys, They are not provided, however there is validation to ensure you have the correct keys.

The keys are commonly called ``unfixed-info.bin`` (data key) and ``locked-secret.bin`` (tag key). Occasionally, these keys are joined for easier loading:

.. code-block:: bash

    cat unfixed-info.bin locked-secret.bin > key.bin

These are binary files of 80 bytes each. Sometimes, they are distributed as hexadecimal bytes separated by spaces (e.g. ``F1 A3 65 ..`` etc). PyAmiibo can also parse this data into binary.

The tag master key is used to derive a Amiibo-specific tag key to sign fixed/locked information of the Amiibo, such as the UID, the Amiibo type.

The data master key is used to derive several Amiibo-specific data keys to sign and encrypt unfixed/unlocked information of the Amiibo, such as the name, the owner, and game data.

The signing operation is a HMAC-SHA256 using the derived keys, and the encryption operation is AES128 in counter mode using a derived key and initialisation vector.

Classes
-------

.. automodule:: amiibo.keys
    :members:
    :private-members:
    :show-inheritance:
