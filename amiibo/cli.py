from argparse import ArgumentParser, ArgumentTypeError, FileType

from .crypto import AmiiboDump
from .keys import AmiiboMasterKey


def parse_hex(value):
    """Hexadecimal byte validator for argparse."""
    try:
        # split/join to strip newlines, fromhex only strips that > 3.7
        return bytes.fromhex(''.join(value.split()))
    except ValueError as e:
        raise ArgumentTypeError('Not hexadecimal.') from e


def parse_uid(value):
    """NTAG 213/215/216 7 byte UID validator for argparse."""
    uid = parse_hex(value)
    if len(uid) != 7:  # NTAG 213/215/216 always have 7 byte UID
        raise ArgumentTypeError('UID must be 7 bytes.')
    return uid


def load_keys():
    with open('unfixed-info.bin', 'rb') as fp_d, \
            open('locked-secret.bin', 'rb') as fp_t:
        return AmiiboMasterKey.from_separate_bin(
            fp_d.read(), fp_t.read())


def decrypt(args):
    master_keys = load_keys()
    dump = AmiiboDump(master_keys, args.input.read(), is_locked=True)
    dump.unlock()
    data = dump.data
    if args.convert:
        data = dump_to_amiitools(data)
    args.output.write(data)


def encrypt(args):
    master_keys = load_keys()
    data = args.input.read()
    if args.convert:
        data = amiitools_to_dump(data)
    dump = AmiiboDump(master_keys, data, is_locked=False)
    dump.lock()
    dump.unset_lock_bytes()
    args.output.write(dump.data)


def update_uid(args):
    master_keys = load_keys()
    dump = AmiiboDump(master_keys, args.input.read(), is_locked=True)
    dump.unlock()
    dump.uid_bin = args.uid
    dump.lock()
    dump.unset_lock_bytes()
    args.output.write(dump.data)


def hex2bin(args):
    args.output.write(args.hex)


def dump_to_amiitools(dump):
    """Convert a standard Amiibo/NTAG215 dump to the 3DS/amiitools internal
    format.
    """
    internal = bytearray(dump)
    internal[0x000:0x008] = dump[0x008:0x010]
    internal[0x008:0x028] = dump[0x080:0x0A0]
    internal[0x028:0x04C] = dump[0x010:0x034]
    internal[0x04C:0x1B4] = dump[0x0A0:0x208]
    internal[0x1B4:0x1D4] = dump[0x034:0x054]
    internal[0x1D4:0x1DC] = dump[0x000:0x008]
    internal[0x1DC:0x208] = dump[0x054:0x080]
    return internal


def amiitools_to_dump(internal):
    """Convert a 3DS/amiitools internal dump to the standard Amiibo/NTAG215
    dump format."""
    dump = bytearray(internal)
    dump[0x008:0x010] = internal[0x000:0x008]
    dump[0x080:0x0A0] = internal[0x008:0x028]
    dump[0x010:0x034] = internal[0x028:0x04C]
    dump[0x0A0:0x208] = internal[0x04C:0x1B4]
    dump[0x034:0x054] = internal[0x1B4:0x1D4]
    dump[0x000:0x008] = internal[0x1D4:0x1DC]
    dump[0x054:0x080] = internal[0x1DC:0x208]
    return dump


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--3ds', dest='convert', action='store_true',
        help=(
            'Reorder the Amiibo data to match the internal 3DS layout '
            'used by amiitools. Some subcommands ignore this.'
        ))
    parser.set_defaults(func=None)
    subparsers = parser.add_subparsers()

    parser_dec = subparsers.add_parser(
        'decrypt',
        help='Decrypt an Amiibo dump.')
    parser_dec.add_argument(
        'input', type=FileType('rb'),
        help='The input filename.')
    parser_dec.add_argument(
        'output', type=FileType('wb'),
        help='The output filename.')
    parser_dec.set_defaults(func=decrypt)

    parser_enc = subparsers.add_parser(
        'encrypt',
        help='Encrypt an Amiibo dump.')
    parser_enc.add_argument(
        'input', type=FileType('rb'),
        help='The input filename.')
    parser_enc.add_argument(
        'output', type=FileType('wb'),
        help='The output filename.')
    parser_enc.set_defaults(func=encrypt)

    parser_uid = subparsers.add_parser(
        'uid',
        help='Update the UID in Amiibo dump.')
    parser_uid.add_argument(
        'input', type=FileType('rb'),
        help='The input filename.')
    parser_uid.add_argument(
        'uid', type=parse_uid,
        help='The 7 byte UID in hexadecimal form.')
    parser_uid.add_argument(
        'output', type=FileType('wb'),
        help='The output filename.')
    parser_uid.set_defaults(func=update_uid)

    parser_hex = subparsers.add_parser(
        'hex2bin',
        help='Convert hexadecimal bytes to binary.')
    parser_hex.add_argument(
        'hex', type=parse_hex,
        help='Hexadecimally-encoded bytes.')
    parser_hex.add_argument(
        'output', type=FileType('wb'),
        help='The output filename.')
    parser_hex.set_defaults(func=hex2bin)

    args = parser.parse_args()
    if args.func:
        args.func(args)
    else:
        parser.print_help()
