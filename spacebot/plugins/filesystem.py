# -*- coding: utf-8 -*-

import os

from spacebot.plugins import Command, ArgumentInfos


class Directory(int):
	pass


class File(int):
	pass


class Executable(File):
	pass


FS = {
	'/': Directory(0),
	'/bin/': Directory(1),
	'/bin/sh': Executable(14),
	'/bin/true': Executable(15),
	'/bin/false': Executable(16),
	'/bin/bash': Executable(17),
	'/bin/ls': Executable(18),
	'/bin/cat': Executable(19),
	'/bin/find': Executable(20),
	'/bin/cd': Executable(21),
	'/etc/': Directory(2),
	'/etc/passwd': File(11),
	'/etc/shadow': File(12),
	'/var/': Directory(4),
	'/var/log/': Directory(5),
	'/var/log/apache/': Directory(6),
	'/var/log/apache/access.log': File(46),
	'/sbin/': Directory(9),
	'/home/': Directory(22),
	'/home/spaceone/': Directory(50),
	'/home/gizmore/.bash_history': File(65),
	'/home/gizmore/': Directory(39),
}
FS = dict((inode, name) for name, inode in FS.iteritems())
ELF = r'\x7fELF\x02\x01\x01\x00'

FILES = {
	11: 'root:x:0:0:root:/:/bin/false\nmailer:x:100:100:mailer:/var:/bin/false\ngizmore:x:Gizmore:/home/gizmore:/bin/sh\nspaceone:x:SpaceOne:/home/spaceone:/bin/bash\n',
	12: 'Permission denied',
	46: '',
	65: 'sudo su\ncd ~/git\ncd www/challenges/\nfind\ncat dloser/brownos/solution.php\nexit\nfirefox\n',
	14: ELF, 15: ELF, 16: ELF, 17: ELF, 18: ELF, 19: ELF, 20: ELF, 21: ELF,
}


class LS(Command):
	'''list directory contents'''

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
			elif args.color in ('auto', 'always') and isinstance(file_or_dir, Executable):
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

	def register(self):
		parser = super(Cat, self).register()
		parser.add_argument('filename')

	def __call__(self, args):
		return cat(args.filename).splitlines()


def find(filename):
	return dict((name, inode) for inode, name in FS.iteritems())


def cat(filename):
	inode = ls(filename).get('.')
	if inode is None:
		return 'No such file or directory'
	return FILES.get(inode, 'Is a directory')


def ls(directory='/'):
	parent_inode = 0
	root = _ls(parent_inode)
	is_file = False
	for segment in directory.split('/'):
		if is_file:
			return _ls(256)  # will cause a "not a directory" error
		if not segment or segment in ('.',):
			continue
		if segment not in root:
			if segment + '/' in root:
				segment += '/'
			else:
				print 'root', root, segment
				root = {segment: Directory(256)}  # will cause a "no directory" error
		if isinstance(root[segment], Directory):
			root = _ls(root[segment])
			root['..'] = Directory(parent_inode)
			parent_inode = root['.']
		else:
			is_file = True
	filename = os.path.basename(directory)
	if isinstance(root.get(filename), File):
		root = {'.': root[filename], filename: root[filename]}
	return root


def _ls(inode):
	if inode in FILES:
		raise ArgumentInfos('No such file or directory')
	directory = FS.get(inode)
	if not directory:
		raise ArgumentInfos('Not a directory')
	result = dict((get_name(_inode), _inode) for _inode, name in FS.items() if name.startswith(directory) and name != directory and '/' not in name[len(directory):].rstrip('/'))
	result['.'] = inode
	return result


def get_name(inode):
	name = FS.get(inode)
	if not name:
		raise ArgumentInfos('No such file or directory')
	return os.path.basename(name) or os.path.basename(os.path.dirname(name)) or os.path.dirname(name)
