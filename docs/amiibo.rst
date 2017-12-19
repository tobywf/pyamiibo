.. _amiibo:

Amiibo
======

`Amiibos <https://www.nintendo.com/amiibo/>`_ are Nintendo figures with small RFID tags inside them that enables integration with some Wii U, 3DS, and Switch games. With a compatible RFID/NFC reader, the data from the tags can be extracted. This is called a dump.

Dumps
-----

The Amiibo RFID tags happen to be NXP Semiconductor's NTAG215 (see also the :ref:`NTAG` page), which can hold 540 bytes. So Amiibo dumps should be 540 bytes. Sometimes, the configuration pages are omitted, incomplete dumps are 520 bytes.

Password protection
-------------------

NTAG215 offers password protection for memory access, which is used for Amiibos. The password is derived from the tag's 7 byte UID:

.. code-block:: python3

    pw[0] = 0xAA ^ uid[1] ^ uid[3]
    pw[1] = 0x55 ^ uid[2] ^ uid[4]
    pw[2] = 0xAA ^ uid[3] ^ uid[5]
    pw[3] = 0x55 ^ uid[4] ^ uid[6]

The first byte of the UID is always ``0x04`` for NXP tags, and so it doesn't make sense to use it in the password.

Cryptography
------------

On top of the password protection NTAG215 offers, cryptography is used to encrypt and sign some sections of the user data in the tag. `Marcos Del Sol Vives' <https://github.com/socram8888>`_ reverse engineered the Amiibo cryptography in his excellent `amiitool <https://github.com/socram8888/amiitool>`_.

For more information, see the :ref:`master-keys` page.

Classes
-------

.. automodule:: amiibo.crypto
    :members:
    :private-members:
    :show-inheritance:
