.. _ntag:

NTAG
====

NTAG is NXP Semiconductor's name for a family of NFC RFID products. Amiibos use NTAG215 internally. NXP's `NTAG213/215/216 datasheet <https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf>`_ is truly excellent and worth a read. (The code is based on Rev. 3.2 / 2 June 2015 / 265332.)

Many constants/properties for interpreting Amiibo/NTAG215 dumps are sourced from the datasheet; where possible the exact section is indicated.

ISO/IEC 14443-3
---------------

ISO/IEC 14443:2016 is the standard for "Identification cards -- Contactless integrated circuit cards -- Proximity cards", which NFC (and therefore NTAG) products implement. There are four parts:

* `Part 1: Physical characteristics <https://www.iso.org/standard/70170.html>`_
* `Part 2: Radio frequency power and signal interface <https://www.iso.org/standard/66288.html>`_
* `Part 3: Initialization and anticollision <https://www.iso.org/standard/70171.html>`_
* `Part 4: Transmission protocol <https://www.iso.org/standard/70172.html>`_

For interpreting NTAG dumps, only part 3 is interesting, because it details the way the UID is stored and validated.

Unfortunately, getting a PDF of the standard costs real money. They are also very tedious - stick to the NTAG213/215/216 datasheet instead!

Classes
-------

.. automodule:: amiibo.ntag
    :members:
    :private-members:
    :show-inheritance:
