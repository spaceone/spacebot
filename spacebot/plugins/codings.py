# -*- coding: utf-8 -*-

import base64
import binascii

from spacebot.plugins import Command


class Base64(Command):
	"""base64 encode/decode data and print to standard output"""

	exceptions = (binascii.Error,)

	def register(self):
		parser = super(Base64, self).register()
		parser.add_argument('-d', '--decode', action='store_true', help='decode data')
		parser.add_argument('data', nargs='?')

	def __call__(self, args):
		content = '\n'.join(args.stdin) if args.stdin else args.data
		if args.decode:
			return repr(base64.b64decode(content)).lstrip("b").strip("'\"")
		return base64.b64encode(content.encode('UTF-8')).decode("ASCII").rstrip()
