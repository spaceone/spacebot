# -*- coding: utf-8 -*-

from spacebot.plugins import Command, ArgumentInfos


class LS(Command):
	'''list directory contents'''

	threaded = True
	exceptions = ()

	def register(self):
		parser = super(LS, self).register()
		parser.add_argument("-a", "--all", action='store_true', help="do not ignore entries starting with .")
		parser.add_argument('-A', '--almost-all', action='store_true', help='do not list implied . and ..')
		parser.add_argument("-i", "--inode", action='store_true', help="print the index number of each file")
		parser.add_argument('-d', '--directory', action='store_true', help='list directories themselves, not their contents')
		parser.add_argument("-l", action='store_true', help="use a long listing format")
		parser.add_argument('--color', default='always', choices=['always', 'never', 'auto'])
		parser.add_argument("directory", nargs='?', default='/')

	def __call__(self, args):
		files = ls(args.directory) or {'': '.'}
		files = sorted([(k, v) for k, v in files.iteritems()])

		def _colorify(file_or_dir):
			if args.color in ('auto', 'always') and (file_or_dir.endswith('/') or file_or_dir in ('.', '..')):
				file_or_dir = '\x0302%s\x03' % (file_or_dir,)
			elif args.color in ('auto', 'always') and file_or_dir in ('false', 'sh', 'sudo'):
				file_or_dir = '\x0309%s\x03' % (file_or_dir,)
			return file_or_dir

		def _filter(file_or_dir):
			if args.all:
				return True
			if args.almost_all and file_or_dir not in ('.', '..'):
				return True
			return not file_or_dir.startswith('.')

		files = ['%s %s' % (v, _colorify(k)) if args.inode else _colorify(k) for k, v in files if _filter(k)]
		if not args.l:
			return '\t'.join(files)
		return files


class Find(Command):
	'''search for files in a directory hierarchy'''

	threaded = True
	exceptions = ()

	def register(self):
		parser = super(Find, self).register()
		parser.add_argument('-type', choices=['f', 'd'], help='File is of type')
		parser.add_argument("-a", "--all", action='store_true', help="do not ignore entries starting with .")
		parser.add_argument("-i", "--inode", action='store_true', help="print the index number of each file")
		parser.add_argument("directory", nargs='?', default='/')

	def __call__(self, args):
		def _filter(file_or_dir):
			if args.type:
				if args.type == 'f' and file_or_dir.endswith('/'):
					return False
				elif args.type == 'd' and not file_or_dir.endswith('/'):
					return False
			return args.all or not k.startswith('.')
		return ['%s %s' % (v, k) if args.inode else k for k, v in sorted(find(args.directory).iteritems()) if _filter(k)]


class Cat(Command):
	'''concatenate files and print on the standard output'''

	threaded = True
	exceptions = ()

	def register(self):
		parser = super(Cat, self).register()
		parser.add_argument('filename')

	def __call__(self, args):
		return cat(args.filename).splitlines()
