# -*- coding: utf-8 -*-

from spacebot.plugins import Command


class Base64(Command):
	"""base64 encode/decode data and print to standard output"""

	def register(self):
		parser = super(Base64, self).register()
		parser.add_argument('-d', '--decode', action='store_true', help='decode data')
		parser.add_argument('data', nargs='?')

	def __call__(self, args):
		content = '\n'.join(args.stdin) if args.stdin else args.data
		if args.decode:
			return repr(content.decode('base64'))
		return content.encode('base64').rstrip()
