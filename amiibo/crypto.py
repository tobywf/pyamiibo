import hmac
from hashlib import sha256
from itertools import chain

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .countries import COUNTRY_CODES
from .ntag import NTAG215

BACKEND = default_backend()


class AmiiboBaseError(Exception):
    """The base for any Amiibo-related errors.

    When setting properties, :exc:`ValueError` can also be raised.
    """
    pass


class AmiiboDumpLockedError(Exception):
    """Raised if the dump is already decrypted or encrypted, to avoid
    performing the operation twice.
    """
    pass


class AmiiboDumpSizeError(AmiiboBaseError, ValueError):
    """Raised if the dump is less than 520 bytes or more than 540 bytes."""
    pass


class AmiiboHMACError(AmiiboBaseError):
    """Raised if either calculated HMAC doesn't match the stored HMAC."""
    pass


class AmiiboHMACTagError(AmiiboHMACError):
    """Raised if the calculated tag HMAC doesn't match the stored HMAC."""
    pass


class AmiiboHMACDataError(AmiiboHMACError):
    """Raised if the calculated tag HMAC doesn't match the stored HMAC."""
    pass


# pylint: disable=too-many-instance-attributes
class AmiiboDump(NTAG215):
    """Manipulate Amiibo dump data.

    :param tuple master_keys: Must be a tuple of
        :class:`amiibo.keys.AmiiboMasterKey`.
    """

    def _derive_key(self, key, derive_aes):
        # start off with the type string (14 bytes, zero terminated)
        seed = [key.type_string]
        # the only two values I've found for magic_size is 14 and 16
        # but this code generic
        append = 16 - key.magic_size
        # extract two bytes from the user data section and pad
        extract = self.data[0x011:0x013] + b'\x00' * 14
        seed.append(extract[:append])
        # add the magic bytes
        seed.append(key.magic_bytes[:key.magic_size])
        # extract the first 6 bytes of the tag's UID
        uid = self.data[0x000:0x008]
        seed.append(uid)
        seed.append(uid)
        # extract some tag data (pages 0x20 - 0x28)
        user = self.data[0x060:0x080]
        # and xor it with the key padding
        seed.append(bytes(a ^ b for a, b in zip(user, key.xor_pad)))

        seed = bytes(chain.from_iterable(seed))
        assert len(seed) == 78, "Size check for key derived seed failed"

        mac = hmac.new(key.hmac_key, digestmod=sha256)
        mac.update(b'\x00\x01')  # counter (1)
        mac.update(seed)
        derived_bytes = mac.digest()
        hmac_key = derived_bytes[:16]

        if not derive_aes:
            return hmac_key

        mac = hmac.new(key.hmac_key, digestmod=sha256)
        mac.update(b'\x00\x00')  # counter (0)
        mac.update(seed)
        derived_bytes = mac.digest()
        aes_key = derived_bytes[:16]
        aes_iv = derived_bytes[16:]

        return hmac_key, aes_key, aes_iv

    def _derive_keys_and_cipher(self):
        # derive the tag HMAC key
        self.hmac_tag_key = self._derive_key(
            self.tag_master_key, derive_aes=False)
        # derive the data HMAC key
        # as well as the AES key and initialization vector
        self.hmac_data_key, aes_key, aes_iv = self._derive_key(
            self.data_master_key, derive_aes=True)

        return Cipher(
            algorithms.AES(aes_key),
            modes.CTR(aes_iv),
            backend=BACKEND)

    def _derive_hmacs(self):
        """Calculate the tag and data HMACs based on the unlocked dump data.

        Can only be called if the data is unlocked.

        The data HMAC depends on the tag HMAC. This is automatically called
        for :meth:`lock`.

        :returns: (tag_hmac, data_hmac)
        :raises AmiiboDumpLockedError: If the dump is encrypted, the HMACs
            are nonsensical.
        """
        if self.is_locked:
            raise AmiiboDumpLockedError

        # calculate tag HMAC
        tag_hmac = hmac.new(self.hmac_tag_key, digestmod=sha256)
        tag_hmac.update(self.data[0x000:0x008])
        tag_hmac.update(self.data[0x054:0x080])
        tag_hmac = tag_hmac.digest()

        # calculate data HMAC
        data_hmac = hmac.new(self.hmac_data_key, digestmod=sha256)
        data_hmac.update(self.data[0x011:0x034])
        data_hmac.update(self.data[0x0A0:0x208])
        data_hmac.update(tag_hmac)
        data_hmac.update(self.data[0x000:0x008])
        data_hmac.update(self.data[0x054:0x080])
        data_hmac = data_hmac.digest()

        return tag_hmac, data_hmac

    def __init__(self, master_keys, dump, is_locked=True):
        self.data_master_key, self.tag_master_key = master_keys
        self.size = len(dump)

        if self.size < 520:
            raise AmiiboDumpSizeError(
                (
                    'Incomplete dump. Have {} bytes, '
                    'Amiibo data is at least 520 bytes'
                ).format(self.size))
        if self.size > 540:
            raise AmiiboDumpSizeError(
                (
                    'Invalid dump. Have {} bytes, '
                    'NTAG 215 is 540 bytes'
                ).format(self.size))

        super().__init__()
        self.data[:len(dump)] = dump
        self.is_locked = is_locked

        if self.is_locked:
            self.hmac_tag_key = None
            self.hmac_data_key = None
        else:
            self._derive_keys_and_cipher()  # need to calculate HMAC keys

    @property
    def _crypt_block(self):
        """Gets or sets the block of data that is encrypted or decrypted.

        Use :meth:`unlock` or :meth:`lock` to manipulate this instead.

        :raises ValueError: When setting the crypt block, if the
            incorrect number of bytes is passed.
        """
        # must be bytes for cryptography module
        return bytes(self.data[0x014:0x034] + self.data[0x0A0:0x208])

    @_crypt_block.setter
    def _crypt_block(self, value):
        if len(value) != 392:
            raise ValueError('Crypt block value wrong size')

        self.data[0x014:0x034] = value[:0x020]
        self.data[0x0A0:0x208] = value[0x020:]

    def verify(self):
        """Verify both the data and the tag HMAC by calculating the HMACs and
        then comparing them to the stored HMACs.

        Can be useful to validate a dump. If you don't care which HMAC differs,
        you can also catch :exc:`AmiiboHMACError`.

        :raises AmiiboHMACTagError: If the tag HMAC differs.
        :raises AmiiboHMACDataError: If the tag HMAC differs.
        """
        tag_hmac, data_hmac = self._derive_hmacs()

        if not hmac.compare_digest(self.tag_hmac, tag_hmac):
            raise AmiiboHMACTagError

        if not hmac.compare_digest(self.data_hmac, data_hmac):
            raise AmiiboHMACDataError

    def unlock(self, verify=True):
        """Decrypt the encrypted user data block.

        :param bool verify: If ``True``, :meth:`verify` is called to check
            the HMACs after decryption.

        :raises AmiiboDumpLockedError: If the dump has already been unlocked,
            to avoid double decryption.
        """
        if not self.is_locked:
            raise AmiiboDumpLockedError

        # get HMAC keys and cipher key/IV
        cipher = self._derive_keys_and_cipher()
        # decrypt
        decryptor = cipher.decryptor()
        self._crypt_block = (
            decryptor.update(self._crypt_block) +
            decryptor.finalize()
        )
        self.is_locked = False

        if verify:
            self.verify()

    def lock(self):
        """Encrypt the decrypted user data block.

        The HMACs are calculated and overwritten, and :meth:`set_password` is
        called.

        :raises AmiiboDumpLockedError: If the dump has already been locked,
            to avoid double encryption.
        """
        if self.is_locked:
            raise AmiiboDumpLockedError

        # get HMAC keys and cipher key/IV
        cipher = self._derive_keys_and_cipher()
        # update HMACs/sign
        self.tag_hmac, self.data_hmac = self._derive_hmacs()
        # encrypt
        encryptor = cipher.encryptor()
        self._crypt_block = (
            encryptor.update(self._crypt_block) +
            encryptor.finalize()
        )
        self.is_locked = True

        self.set_password()

    @property
    def tag_hmac(self):
        """Gets or sets the tag HMAC.

        The HMAC is retrieved from the dump data, and is not calculated. To
        calculate the HMAC, use :meth:`_derive_hmacs`.

        :raises ValueError: When setting the tag HMAC, if the incorrect number
            of bytes is passed.
        """
        return self.data[0x034:0x054]

    @tag_hmac.setter
    def tag_hmac(self, value):
        if len(value) != 0x20:
            raise ValueError
        self.data[0x034:0x054] = value

    @property
    def data_hmac(self):
        """Gets or sets the data HMAC.

        The HMAC is retrieved from the dump data, and is not calculated. To
        calculate the HMAC, use :meth:`_derive_hmacs`.

        :raises ValueError: When setting the data HMAC, if the incorrect number
            of bytes is passed.
        """
        return self.data[0x080:0x0A0]

    @data_hmac.setter
    def data_hmac(self, value):
        if len(value) != 0x20:
            raise ValueError
        self.data[0x080:0x0A0] = value

    def set_password(self):
        """Sets the NTAG memory protection password to a value derived from
        the tag's UID.

        The password is outside the user data, and not included in the HMACs,
        so this step can be done at any time.

        :raises AssertionError: If the UID doesn't start with ``0x04``.
        """
        uid = self.uid_bin
        assert uid[0] == 0x04  # All NXP tags start with this
        self.password = bytes([
            0xAA ^ uid[1] ^ uid[3],
            0x55 ^ uid[2] ^ uid[4],
            0xAA ^ uid[3] ^ uid[5],
            0x55 ^ uid[4] ^ uid[6],
        ])
        self.password_ack = b'\x80\x80'

    @property
    def character_id(self):
        return (self.data[0x058] << 8) | (self.data[0x059])

    @character_id.setter
    def character_id(self, char_id):
        if char_id < 0 or char_id > 0xFFFF:
            raise ValueError
        self.data[0x058] = (char_id >> 8) & 0xFF
        self.data[0x059] = (char_id >> 0) & 0xFF

    @property
    def game_series(self):
        # ugh, nibbles
        return (self.data[0x054] << 4) | (self.data[0x055] >> 4)

    @game_series.setter
    def game_series(self, series):
        if series < 0 or series > 0xFFF:
            raise ValueError
        # ugh, nibbles
        self.data[0x054] = series >> 4
        self.data[0x055] = ((series & 0xF) << 4) | (self.data[0x055] & 0xF)

    @property
    def character_index(self):
        # ugh, nibbles
        return self.data[0x055] & 0xF

    @character_index.setter
    def character_index(self, index):
        if index < 0 or index > 0xF:
            raise ValueError
        # ugh, nibbles
        self.data[0x055] = (self.data[0x055] & 0xF0) | index

    @property
    def amiibo_nickname(self):
        # TODO: why is the Amiibo nickname big endian,
        # but the Mii nickname litle endian?
        return self.data[0x020:0x034].decode('utf-16-be').rstrip('\x00')

    @amiibo_nickname.setter
    def amiibo_nickname(self, name):
        utf16 = name.encode('utf-16-be')
        if len(utf16) > 20:
            raise ValueError
        self.data[0x020:0x034] = utf16.ljust(20, b'\x00')

    @property
    def owner_nickname(self):
        # TODO: why is the Amiibo nickname big endian,
        # but the Mii nickname litle endian?
        return self.data[0x0BA:0x0CE].decode('utf-16-le').rstrip('\x00')

    @owner_nickname.setter
    def owner_nickname(self, name):
        utf16 = name.encode('utf-16-le')
        if len(utf16) > 20:
            raise ValueError
        self.data[0x0BA:0x0CE] = utf16.ljust(20, b'\x00')

    @property
    def write_counter(self):
        return (self.data[0x108] << 8) | self.data[0x109]

    @write_counter.setter
    def write_counter(self, counter):
        if counter < 0 or counter > 0xFFFF:
            raise ValueError
        self.data[0x108] = (counter >> 8) & 0xFF
        self.data[0x109] = (counter >> 0) & 0xFF

    @property
    def app_id(self):
        return self.data[0x10a:0x10e]

    @app_id.setter
    def app_id(self, value):
        if len(value) != 4:
            raise ValueError
        self.data[0x10a:0x10e] = value

    @property
    def country_code(self):
        return self.data[0x015]

    @country_code.setter
    def country_code(self, code):
        if code < 0 or code > 0xFF:
            raise ValueError
        self.data[0x015] = code

    @property
    def country_name(self):
        return COUNTRY_CODES.get(self.country_code, 'Unknown')
