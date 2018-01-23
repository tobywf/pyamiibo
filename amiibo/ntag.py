from enum import Enum


class NTAGUIDError(Exception):
    """Raised if the check byte validation of the UID fails."""
    pass


class NTAGCounterError(Exception):
    """Raised if the NFC counter is read but it is not enabled."""
    pass


class MirrorConf(Enum):
    """Possible configurations for the ASCII mirror function.
    (8.7 ASCII mirror function)
    """

    #: No ASCII mirroring is performed (default).
    NO_ASCII_MIRROR = 0b00
    #: The UID is mirrored to physical memory (14 bytes).
    UID_ASCII_MIRROR = 0b01
    #: The NFC counter is mirrored to physical memory (6 bytes).
    CTR_ASCII_MIRROR = 0b10
    #: Both the UID and the NFC counter are mirrored to physical memory
    #: separated by ``'x'``/``0x78`` (14 + 1 + 6 = 21 bytes).
    BOTH_ASCII_MIRROR = 0b11


def bit_test(byte, bit):
    if bit < 0 or bit > 7:
        raise ValueError
    mask = (1 << bit)
    return (byte & mask) == mask


def bit_set(byte, bit, value):
    if bit < 0 or bit > 7:
        raise ValueError
    mask = 1 << bit
    if value:
        byte |= mask
    else:
        byte &= (~mask) & 0xFF
    return byte


# pylint: disable=too-many-public-methods
class NTAGBase:
    """The base for the NTAG213/215/216 classes contains most functionality
    for extracting NTAG properties from a binary dump.

    ``data`` must be a :class:`bytearray`. If ``data`` is not specified,
    a :class:`bytearray` of the appropriate size for the tag is assigned.
    """

    #: Cascade Tag for UIDs > 4 bytes
    #: (``0x88``, as defined in `ISO/IEC 14443-3`_).
    CT = 0x88
    #: The page size in bytes. (8.5 Memory organization)
    PAGE_SIZE = 4
    SIZE = 0
    DYN_OFFSET = 0

    def __init__(self, data=None):
        if not data:
            self.data = bytearray(self.SIZE)

    @property
    def _uid_raw(self):
        """Gets the raw 7 byte UID. Check bytes are not validated.
        (8.5 Memory organization)
        """
        return self.data[0:3] + self.data[4:8]

    @property
    def uid_bin(self):
        """Gets or sets the 7 byte UID. (8.5.1 UID/serial number)

        When getting the UID, the check bytes are tested.
        When setting the UID, the check bytes are calculated.

        UID and check bytes are defined in `ISO/IEC 14443-3`_.

        :raises NTAGUIDError: When getting the UID, if validation fails.
        :raises ValueError: When setting the UID, if more or less than 7
            bytes were supplied.
        """
        uid = self._uid_raw
        assert len(uid) == 7, 'Internal error (UID incorrect size)'

        bcc0 = self.data[3]
        bcc1 = self.data[8]

        check = NTAGBase.CT ^ uid[0] ^ uid[1] ^ uid[2]
        if check != bcc0:
            raise NTAGUIDError('UID check failed (0)')

        check = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
        if check != bcc1:
            raise NTAGUIDError('UID check failed (1)')

        return uid

    @uid_bin.setter
    def uid_bin(self, uid):
        if len(uid) != 7:
            raise ValueError('UID incorrect size: {} != 7'.format(len(uid)))

        # BCC 0
        self.data[3] = NTAGBase.CT ^ uid[0] ^ uid[1] ^ uid[2]
        # BCC 1
        self.data[8] = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]

        self.data[0:3] = uid[0:3]
        self.data[4:8] = uid[3:7]

    @property
    def uid_hex(self):
        """Gets or sets the 7 byte UID as a hexadecimal digit string.

        When getting the UID, bytes are separated by spaces.

        Please refer to :attr:`uid_bin` for possible errors.
        """
        return ' '.join('{:02X}'.format(b) for b in self.uid_bin)

    @uid_hex.setter
    def uid_hex(self, uid):
        self.uid_bin = bytes.fromhex(uid)

    @property
    def _static_lock_bytes(self):
        """Gets or sets the raw static lock bytes.
        (8.5.2 Static lock bytes (NTAG21x))

        :raises AssertionError: When setting the static lock bytes,
            if the incorrect number of bytes was passed.
        """
        return self.data[10:12]

    @_static_lock_bytes.setter
    def _static_lock_bytes(self, values):
        assert len(values) == 2
        self.data[10:12] = values

    @property
    def _capability_container(self):
        """Gets or sets the raw capability container bytes.
        (8.5 Memory organization)

        :raises AssertionError: When setting the capability container bytes,
            if the incorrect number of bytes was passed.
        """
        return self.data[12:16]

    @_capability_container.setter
    def _capability_container(self, values):
        assert len(values) == 4
        self.data[12:16] = values

    @property
    def _dynamic_lock_bytes(self):
        """Gets or sets the raw dynamic lock bytes.
        (8.5.3 Dynamic Lock Bytes)

        :raises AssertionError: When setting the dynamic lock bytes,
            if the incorrect number of bytes was passed.
        """
        return self.data[self.DYN_OFFSET:self.DYN_OFFSET + 3]

    @_dynamic_lock_bytes.setter
    def _dynamic_lock_bytes(self, values):
        assert len(values) == 3
        self.data[self.DYN_OFFSET:self.DYN_OFFSET + 3] = values

    @property
    def _config_pages(self):
        """Gets or sets the raw configuration page bytes.
        (8.5 Memory organization)

        :raises AssertionError: When setting the configuration page bytes,
            if the incorrect number of bytes was passed.
        """
        return self.data[self.DYN_OFFSET + 4:self.DYN_OFFSET + 16]

    @property
    def static_pages_locked(self):
        """A list of the lock status of the first 16 pages (0-15).
        (8.5.2 Static lock bytes (NTAG21x))

        Each item is ``True`` if the page is locked; otherwise, ``False``.
        Pages 0-2 (UID) are always locked and cannot be changed.

        :raises ValueError: When setting the static lock pages, if a
            sequence of length unequal to 16 was passed.
        :raises ValueError: When setting the static lock pages, if the
            first 3 pages are attempted to be changed to unlocked.
        """
        # 0b111 = first three pages (UID) are always locked
        lock = (self.data[11] << 8) | self.data[10] | 0b111
        return [(lock & (1 << i)) != 0 for i in range(16)]

    @static_pages_locked.setter
    def static_pages_locked(self, pages):
        if len(pages) != 16:
            raise ValueError('Incorrect number of pages')

        lock = sum((1 << i) for i, value in enumerate(pages) if value)

        if (lock & 0b111) != 0b111:
            raise ValueError('Cannot change lock status of pages 0-2')

        self.data[11] = (lock >> 8)
        # preserve block-locking bits
        self.data[10] = (lock & 0b11111000) | (self.data[10] & 0b111)

    def unset_static_lock_bytes(self):
        """Unset all static block-locking and page-locking (default values).
        (8.5.2 Static lock bytes (NTAG21x))
        """
        self.data[11] = 0
        self.data[10] = 0

    def unset_dynamic_lock_bytes(self):
        """Unset all dynamic page-locking (default values).
        (8.5.3 Dynamic Lock Bytes)
        """
        self._dynamic_lock_bytes = b'\x00\x00\x00'

    def unset_lock_bytes(self):
        """Unset static and dynamic lock bytes.

        See :meth:`unset_static_lock_bytes` and
        :meth:`unset_dynamic_lock_bytes`.
        """
        self.unset_static_lock_bytes()
        self.unset_dynamic_lock_bytes()

    @property
    def static_block_locked(self):
        """A list of the lock status of the three static lock blocks (0-2).
        (8.5.2 Static lock bytes (NTAG21x))

        On the tag, the static block-locking bytes determine whether the static
        page-locking bytes can be changed:

        * Block 0 locks the lock bit for page 3 (CC)
        * Block 1 locks the lock bits for pages 4-9
        * Block 2 locks the lock bits for pages 10-15

        Each item is ``True`` if the block is locked; otherwise, ``False``.

        :raises ValueError: When setting the static lock blocks, if a
            sequence of length unequal to 3 was passed.
        """
        return [
            (self.data[10] & 0b001) != 0,
            (self.data[10] & 0b010) != 0,
            (self.data[10] & 0b100) != 0,
        ]

    @static_block_locked.setter
    def static_block_locked(self, blocks):
        if len(blocks) != 3:
            raise ValueError('Incorrect number of blocks')

        lock = sum((1 << i) for i, value in enumerate(blocks) if value)

        # preserve page-locking bits
        self.data[10] = (self.data[10] & 0b11111000) | (lock & 0b111)

    def static_page_get_locked(self, page):
        if page < 3 or page > 15:
            raise ValueError('Invalid page: 3 =< {} =< 15'.format(page))

        if page < 8:
            return bit_test(self.data[10], page)
        return bit_test(self.data[11], page - 8)

    def static_page_set_locked(self, page, status):
        if page < 3 or page > 15:
            raise ValueError('Invalid page: 3 =< {} =< 15'.format(page))

        if page < 8:
            self.data[10] = bit_set(self.data[10], page, status)
        else:
            self.data[11] = bit_set(self.data[11], page - 8, status)

    @property
    def mirror_conf(self):
        """Gets or sets what type of ASCII mirror is used.
        (8.7 ASCII mirror function)

        Default is :attr:`MirrorConf.NO_ASCII_MIRROR` (``0b00``).
        """
        mirror = self.data[self.DYN_OFFSET + 4]
        return MirrorConf((mirror >> 6) & 0b11)

    @mirror_conf.setter
    def mirror_conf(self, conf):
        value = conf.value & 0b11
        mirror = self.data[self.DYN_OFFSET + 4]
        mirror = (value << 6) | (mirror & 0b00111111)
        self.data[self.DYN_OFFSET + 4] = mirror

    @property
    def mirror_byte(self):
        """Gets or sets the byte position for the ASCII mirror inside
        the mirror page. (8.7 ASCII mirror function)

        Default is ``0b00``.
        """
        mirror = self.data[self.DYN_OFFSET + 4]
        return (mirror >> 4) & 0b11

    @mirror_byte.setter
    def mirror_byte(self, byte):
        if byte < 0 or byte >= NTAGBase.PAGE_SIZE:
            raise ValueError('Invalid mirror byte')

        value = byte & 0b11
        mirror = self.data[self.DYN_OFFSET + 4]
        mirror = (value << 4) | (mirror & 0b11001111)
        self.data[self.DYN_OFFSET + 4] = mirror

    @property
    def strong_modulation(self):
        """Gets or sets whether strong modulation is enabled.

        Default is ``True`` (``0b1``)."""
        mirror = self.data[self.DYN_OFFSET + 4]
        return bit_test(mirror, 2)

    @strong_modulation.setter
    def strong_modulation(self, enabled):
        mirror = self.data[self.DYN_OFFSET + 4]
        mirror = bit_set(self.data[self.DYN_OFFSET + 4], 2, enabled)
        self.data[self.DYN_OFFSET + 4] = mirror

    @property
    def mirror_page(self):
        """Gets or sets the page for the ASCII mirror.
        (8.7 ASCII mirror function)

        Default is ``0x00``. Values > 3 enable the ASCII mirror.
        """
        return self.data[self.DYN_OFFSET + 6]

    @mirror_page.setter
    def mirror_page(self, page):
        # I don't know what happens if you set the page to more than the
        # tag supports. The datasheet seems to indicate that if you don't
        # leave enough space, simply nothing will be mirrored.
        # (8.7 ASCII mirror function)
        if page < 0 or page > 255:
            raise ValueError('Invalid mirror page')

        self.data[self.DYN_OFFSET + 6] = page

    @property
    def mirror_offset(self):
        """Gets or sets the byte offset for the ASCII mirror.

        Both the mirror byte and mirror page will be updated. No validation
        is performed, but an error may be raised if mirror page > 255.
        """
        return self.mirror_page * NTAGBase.PAGE_SIZE + self.mirror_byte

    @mirror_offset.setter
    def mirror_offset(self, offset):
        self.mirror_page, self.mirror_byte = divmod(offset, NTAGBase.PAGE_SIZE)

    @property
    def auth_page(self):
        """Gets or sets the start page for which password verification is
        required. (8.8 Password verification protection)

        Default is ``0xFF``. Values higher than the last page of the user
        configuration disable the password verification.
        """
        return self.data[self.DYN_OFFSET + 7]

    @auth_page.setter
    def auth_page(self, page):
        if page < 0 or page > 255:
            raise ValueError('Invalid auth page')

        self.data[self.DYN_OFFSET + 7] = page

    @property
    def read_protection(self):
        """Gets or sets whether read access is protected by the password
        verification. (8.8.3 Protection of special memory segments)

        Default is ``False`` (``0b0``)."""
        access = self.data[self.DYN_OFFSET + 8]
        return bit_test(access, 7)

    @read_protection.setter
    def read_protection(self, enabled):
        access = self.data[self.DYN_OFFSET + 8]
        access = bit_set(access, 7, enabled)
        self.data[self.DYN_OFFSET + 8] = access

    @property
    def config_lock(self):
        """Gets or sets whether the user configuration is locked for writes.
        (8.5.7. Configuration pages)

        Default is ``False`` (``0b0``)."""
        access = self.data[self.DYN_OFFSET + 8]
        return bit_test(access, 6)

    @config_lock.setter
    def config_lock(self, enabled):
        access = self.data[self.DYN_OFFSET + 8]
        access = bit_set(access, 6, enabled)
        self.data[self.DYN_OFFSET + 8] = access

    @property
    def nfc_counter_enabled(self):
        """Gets or sets whether the NFC counter is enabled.
        (8.6 NFC counter function)

        Default is ``False`` (``0b0``)."""
        access = self.data[self.DYN_OFFSET + 8]
        return bit_test(access, 4)

    @nfc_counter_enabled.setter
    def nfc_counter_enabled(self, enabled):
        access = self.data[self.DYN_OFFSET + 8]
        access = bit_set(access, 4, enabled)
        self.data[self.DYN_OFFSET + 8] = access

    @property
    def nfc_counter_password_protection(self):
        """Gets or sets whether NFC counter password protection is enabled.
        (8.6 NFC counter function/8.8 Password verification protection)

        Default is ``False`` (``0b0``)."""
        access = self.data[self.DYN_OFFSET + 8]
        return bit_test(access, 3)

    @nfc_counter_password_protection.setter
    def nfc_counter_password_protection(self, enabled):
        access = self.data[self.DYN_OFFSET + 8]
        access = bit_set(access, 3, enabled)
        self.data[self.DYN_OFFSET + 8] = access

    def _validate_nfc_counter(self):
        conf = self.mirror_conf
        if conf == MirrorConf.CTR_ASCII_MIRROR:
            size = 6
            skip = 0
        elif conf == MirrorConf.BOTH_ASCII_MIRROR:
            size = 21
            skip = 15
        else:
            raise NTAGCounterError('Counter mirror not enabled')

        offset = self.mirror_offset
        if offset < 4 * NTAGBase.PAGE_SIZE:
            raise NTAGCounterError('Counter mirror offset invalid')

        if offset > self.DYN_OFFSET - size:
            raise NTAGCounterError('Counter mirror offset invalid')

        return offset + skip

    @property
    def nfc_counter_value(self):
        """Gets or sets the NFC counter value.
        (8.6 NFC counter function)

        Since we only have the dump, not the tag to issue ``READ_CNT``,
        the ASCII mirror of the NFC counter must have been enabled.

        This property converts the ASCII NFC counter value to an integer.

        :raises NTAGCounterError: If the ASCII mirror is not configured to
            mirror the NFC counter (either :attr:`MirrorConf.CTR_ASCII_MIRROR`
            or :attr:`MirrorConf.BOTH_ASCII_MIRROR`), or the offset determined
            by the mirror page and mirror byte is invalid.
        """
        offset = self._validate_nfc_counter()
        ascii_mirror = self.data[offset:offset + 6].decode('ascii')
        return int(ascii_mirror, 16)

    @nfc_counter_value.setter
    def nfc_counter_value(self, counter):
        if counter < 0 or counter > 0xFFFFFF:
            raise ValueError
        offset = self._validate_nfc_counter()
        self.data[offset:offset + 6] = '{:06X}'.format(counter).encode('ascii')

    @property
    def authentication_limit(self):
        """Gets or sets the (negative) password verification attempt limit.
        (8.8.2 Limiting negative verification attempts)

        Default is ``0b000``, which disables limiting incorrect password
        verification attempts.
        """
        access = self.data[self.DYN_OFFSET + 8]
        return (access >> 0) & 0b110

    @authentication_limit.setter
    def authentication_limit(self, limit):
        if limit < 0 or limit > 0b111:
            raise ValueError('Invalid authentication limit')

        value = limit & 0b111
        access = self.data[self.DYN_OFFSET + 8]
        access = (value << 0) | (access & 0b11111000)
        self.data[self.DYN_OFFSET + 8] = access

    @property
    def password(self):
        """Gets or sets the 4 byte memory access protection password.
        (8.8 Password verification protection)

        Default is ``b'\\xFF\\xFF\\xFF\\xFF'``, however the password cannot
        be read, and ``b'\\x00\\x00\\x00\\x00'`` is returned (and typical).
        """
        return self.data[self.DYN_OFFSET + 12:self.DYN_OFFSET + 16]

    @password.setter
    def password(self, value):
        if len(value) != 4:
            raise ValueError
        self.data[self.DYN_OFFSET + 12:self.DYN_OFFSET + 16] = value

    @property
    def password_ack(self):
        """Gets or sets the 2 byte password acknowledge.
        (8.8 Password verification protection)

        Default is ``b'\\x00\\x00'``, however the password acknowledge cannot
        be read.
        """
        return self.data[self.DYN_OFFSET + 16:self.DYN_OFFSET + 18]

    @password_ack.setter
    def password_ack(self, value):
        if len(value) != 2:
            raise ValueError
        self.data[self.DYN_OFFSET + 16:self.DYN_OFFSET + 18] = value


class NTAG213(NTAGBase):
    #: The total number of pages in this tag type. (8.5 Memory organization)
    PAGES = 45
    #: The total size in bytes of this tag type. (8.5 Memory organization)
    SIZE = PAGES * NTAGBase.PAGE_SIZE
    #: The dynamic lock bytes offset in bytes for this tag type.
    #: (8.5 Memory organization)
    DYN_OFFSET = (PAGES - 5) * NTAGBase.PAGE_SIZE

    #: The initial value of the capability container.
    #: (8.5.6 Memory content at delivery)
    CAPABILITY_CONTAINER = b'\xE1\x10\x12\x00\x01\x03\xA0\x0C\x34\x03\x00\xFE'


class NTAG216(NTAGBase):
    #: The total number of pages in this tag type. (8.5 Memory organization)
    PAGES = 231
    #: The total size in bytes of this tag type. (8.5 Memory organization)
    SIZE = PAGES * NTAGBase.PAGE_SIZE
    #: The dynamic lock bytes offset in bytes for this tag type.
    #: (8.5 Memory organization)
    DYN_OFFSET = (PAGES - 5) * NTAGBase.PAGE_SIZE

    #: The initial value of the capability container.
    #: (8.5.6 Memory content at delivery)
    CAPABILITY_CONTAINER = b'\xE1\x10\x6D\x00\x03\x00\xFE\x00\x00\x00\x00\x00'


class NTAG215(NTAGBase):
    #: The total number of pages in this tag type. (8.5 Memory organization)
    PAGES = 135
    #: The total size in bytes of this tag type. (8.5 Memory organization)
    SIZE = PAGES * NTAGBase.PAGE_SIZE
    #: The dynamic lock bytes offset in bytes for this tag type.
    #: (8.5 Memory organization)
    DYN_OFFSET = (PAGES - 5) * NTAGBase.PAGE_SIZE

    #: The initial value of the capability container.
    #: (8.5.6 Memory content at delivery)
    CAPABILITY_CONTAINER = b'\xE1\x10\x3E\x00\x03\x00\xFE\x00\x00\x00\x00\x00'
