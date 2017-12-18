from hashlib import sha256
from struct import unpack


class AmiiboMasterKey:
    """Helper class to validate and unpack crypto master keys.

    The keys are commonly called ``unfixed-info.bin`` (data key) and
    ``locked-secret.bin`` (tag key).
    """
    KEY_FMT = '=16s14sBB16s32s'

    DATA_BIN_SHA256_HEXDIGEST = \
        '868106135941cbcab3552bd14880a7a34304ef340958a6998b61a38ba3ce13d3'
    TAG_BIN_SHA256_HEXDIGEST = \
        'b48727797cd2548200b99c665b20a78190470163ccb8e5682149f1b2f7a006cf'

    def __init__(self, data, sha256_digest):
        count = len(data)
        if count != 80:
            raise ValueError('Data is {} bytes (should be 80).'.format(count))

        digest = sha256(data).hexdigest()
        if digest != sha256_digest:
            raise ValueError(
                (
                    'Data failed check, may be corrupt\n'
                    '{} != {}'
                ).format(digest, sha256_digest))

        (
            self.hmac_key,      # 16 bytes
            self.type_string,   # 14 bytes
            self.rfu,           # 1 byte reserved for future use, padding
            self.magic_size,    # 1 byte
            self.magic_bytes,   # 16 bytes
            self.xor_pad        # 32 bytes
        ) = unpack(self.KEY_FMT, data)

    @classmethod
    def from_separate_bin(cls, data_bin, tag_bin):
        """Given the data and tag master keys in binary, validate and
        unpack them.

        :param bytes data_bin: The binary data master key
        :param bytes tag_bin: The binary tag master key
        :return: Two instances of :class:`AmiiboMasterKey`.
        :raises ValueError: If the binary data is invalid
        """
        data = cls(data_bin, cls.DATA_BIN_SHA256_HEXDIGEST)
        tag = cls(tag_bin, cls.TAG_BIN_SHA256_HEXDIGEST)
        return data, tag

    @classmethod
    def from_separate_hex(cls, data_str, tag_str):
        """Given the data and tag master keys in hexadecimal, validate and
        unpack them.

        :param str data_bin: The hexadecimal data master key
        :param str tag_bin: The hexadecimal tag master key
        :return: Two instances of :class:`AmiiboMasterKey`.
        :raises ValueError: If the hexadecimal data is invalid
        """
        return cls.from_separate_bin(
            bytes.fromhex(data_str),
            bytes.fromhex(tag_str))

    @classmethod
    def from_combined_bin(cls, combined_bin):
        """Given the data and tag master keys in binary, validate and
        unpack them.

        :param bytes combined_bin: The binary data and tag master key
        :return: Two instances of :class:`AmiiboMasterKey`.
        :raises ValueError: If the binary data is invalid
        """
        count = len(combined_bin)
        if count != 160:
            raise ValueError('Data is {} bytes (should be 160).'.format(count))

        return cls.from_separate_bin(combined_bin[:80], combined_bin[80:])
