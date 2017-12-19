PyAmiibo
========

PyAmiibo helps to read, modify and write dump files of `Nintendo Amiibo figures <https://www.nintendo.com/amiibo/>`_. PyAmiibo is capable of parsing most NTAG properties, as well as some Amiibo data.

**IMPORTANT**: To decrypt and encrypt Amiibo data, you will need two master keys, commonly called ``unfixed-info.bin`` and ``locked-secret.bin``. They are not provided.

You can also view the `full PyAmiibo docs on ReadTheDocs <http://pyamiibo.readthedocs.io/en/latest/>`_.

------

It is based on `Marcos Del Sol Vives' <https://github.com/socram8888>`_ reverse engineering efforts of the Amiibo cryptography (`amiitool <https://github.com/socram8888/amiitool>`_, `reddit <https://www.reddit.com/r/amiibros/comments/328hqz/amiibo_encryption_reverseengineering/>`_).

So why does PyAmiibo exist? ``amiitool`` is a C binary, difficult to use in other tools (especially web-based tools). It also re-arranges the sections of the dump file when decrypting, and doesn't seem to support editing dumps (e.g. changing the UID). Even though PyAmiibo doesn't use any of ``amiitool``'s code and contains a lot of my own research into the NTAG format and Amiibo data, it would not have been possible without Marcos' efforts.

Usage
=====

**PyAmiibo is Python 3 only**, if you get an error installing it this is the most likely reason.

.. code-block:: bash

    pip install pyamiibo

PyAmiibo is mainly a library, but also contains some simple command-line tools:

.. code-block:: console

    $ # convert hexadecimal data to binary, note the quotes!
    $ amiibo hex2bin "F1 A3 65 .." unfixed-info.bin
    $ # get help for a subcommand
    $ amiibo uid --help
    $ # update the UID on an existing dump
    $ amiibo uid old.bin "04 FF FF FF FF FF FF" new.bin

The master keys must be in the current directory for some commands to work!

It's also very easy to use in a script or interpreter session:

.. code-block:: python3

    from amiibo import AmiiboDump, AmiiboMasterKey
    with open('unfixed-info.bin', 'rb') as fp_d, \
            open('locked-secret.bin', 'rb') as fp_t:
        master_keys = AmiiboMasterKey.from_separate_bin(
            fp_d.read(), fp_t.read())

    with open('dump.bin', 'rb') as fp:
        dump = AmiiboDump(master_keys, fp.read())

    print('old', dump.uid_hex)
    dump.unlock()
    dump.uid_hex = '04 FF FF FF FF FF FF'
    dump.lock()
    dump.unset_lock_bytes()
    print('new', dump.uid_hex)

    with open('new.bin', 'wb') as fp:
        fp.write(dump.data)

Development
===========

Use `pipenv <https://docs.pipenv.org>`_ to install the development dependencies, and make sure ``flake8`` and ``pylint`` pass before a PR is submitted.

.. code-block:: bash

    pipenv install --three --dev
    pipenv shell
    isort -y
    flake8 amiibo/
    pylint amiibo/
    sphinx-build -b html docs/ docs/_build
