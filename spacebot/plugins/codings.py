# -*- coding: utf-8 -*-

import base64
import binascii

from spacebot.plugins import Command


class Base64(Command):
    """base64 encode/decode data and print to standard output"""

    exceptions = (binascii.Error,)

    def register(self):
        parser = super().register()
        parser.add_argument('-d', '--decode', action='store_true', help='decode data')
        parser.add_argument('data', nargs='?')

    def __call__(self, args):
        content = '\n'.join(args.stdin) if args.stdin else args.data
        if args.decode:
            return repr(base64.b64decode(content)).lstrip('b').strip('\'"')
        return base64.b64encode(content.encode('UTF-8')).decode('ASCII').rstrip()


def obfuscate(string):
    chars = {
        b'A': b'\xce\x91',
        b'B': b'\xce\x92',
        b'C': b'\xd0\xa1',
        b'E': b'\xce\x95',
        b'F': b'\xcf\x9c',
        b'H': b'\xce\x97',
        b'I': b'\xce\x99',
        b'J': b'\xd0\x88',
        b'K': b'\xce\x9a',
        b'M': b'\xce\x9c',
        b'N': b'\xce\x9d',
        b'O': b'\xce\x9f',
        b'P': b'\xce\xa1',
        b'S': b'\xd0\x85',
        b'T': b'\xce\xa4',
        b'X': b'\xce\xa7',
        b'Y': b'\xce\xa5',
        b'Z': b'\xce\x96',
        b'a': b'\xd0\xb0',
        b'c': b'\xd1\x81',
        b'e': b'\xd0\xb5',
        b'i': b'\xd1\x96',
        b'j': b'\xd1\x98',
        b'o': b'\xd0\xbe',
        b'p': b'\xd1\x80',
        b's': b'\xd1\x95',
        b'x': b'\xd1\x85',
        b'y': b'\xd1\x83',
    }
    text = isinstance(string, str)
    if text:
        string = string.encode('utf-8')
    for key, val in chars.items():
        string = string.replace(key, val)
    if text:
        string = string.decode('utf-8')
    return string


class Obfuscate(Command):
    """replace chars with UTF-8 look alikes"""

    def register(self):
        parser = super().register()
        parser.add_argument('string', nargs='?')

    def __call__(self, args):
        content = '\n'.join(args.stdin) if args.stdin else args.string
        return obfuscate(content).rstrip()
