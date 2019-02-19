# -*- coding: utf-8 -*-
import sys
import shlex
import argparse
import traceback
import textwrap
import datetime
import hashlib
import requests
import urllib

import pytz

from circuits import BaseComponent, task, handler, Event, Debugger, Worker
from circuits.protocols.irc import PRIVMSG, NICK, JOIN, PART, QUIT
from circuits.protocols.irc.utils import strip


class ArgumentParserError(Exception):
	pass


class ArgumentInfos(Exception):
	pass


class ArgumentParser(argparse.ArgumentParser):

	def error(self, message):
		raise ArgumentParserError(message)

	def print_help(self, file=None):
		self.show_help = True

	def parse_args(self, args=None, namespace=None, decode=True):
		self.show_help = False
		if isinstance(args, basestring):
			args = args.encode('utf-8')
			try:
				args = shlex.split(args.replace('\\', '\\\\'))
			except ValueError as exc:
				raise ArgumentParserError('Invalid args: %s' % (exc,))
			args = [arg.decode('utf-8', 'replace') for arg in args]

		try:
			return super(ArgumentParser, self).parse_args(args, namespace)
		except SystemExit:
			pass
		if self.show_help:
			raise ArgumentInfos(self.format_help().strip())


class Command(object):

	threaded = False
	exceptions = ()
	public = False
	admin = False
	private = False
	ignore_argument_errors = False

	@property
	def name(self):
		return type(self).__name__.lower().decode('utf-8')

	def __init__(self, bot):
		self._commander = bot

	def __call__(self, args):
		return

	def register(self, *args, **kwargs):
		return self.add_command(*args, help=self.__doc__, public=self.public, admin=self.admin, private=self.private, threaded=self.threaded, exceptions=self.exceptions, ignore_argument_errors=self.ignore_argument_errors, **kwargs)

	def add_command(self, *args, **kwargs):
		return self._commander.add_command(self.name.encode('utf-8'), self, *args, **kwargs)


class Grep(Command):
	'''print lines matching a pattern'''

	public = True

	def register(self):
		parser = super(Grep, self).register()
		parser.add_argument('-v', '--invert-match', action='store_true', help='Invert the sense of matching, to select non-matching lines.')
		parser.add_argument('pattern')

	def __call__(self, args):
		lines = args.stdin or []
		return [line for line in lines if ((args.pattern not in line) if args.invert_match else (args.pattern in line))]


class Echo(Command):
	'''display a line of text'''

	public = True

	def register(self):
		parser = super(Echo, self).register(True)
		parser.add_argument('-e', action='store_true', help='enable interpretation of backslash escapes')

	def __call__(self, args):
		string = ' '.join(args.args)
		string.replace('$?', '0' if args.stdin else '1')
		if args.e:
			string = string.replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t')
		string = string.splitlines()
		if len(string) > 4:
			string = string[:3] + ['...']
		return string


class Tail(Command):
	'''output the last part of files'''

	public = True

	def register(self):
		parser = super(Tail, self).register()
		parser.add_argument('-n', '--lines', default=10, type=int)

	def __call__(self, args):
		return (args.stdin or [])[-args.lines:]


class Head(Command):
	'''output the first part of files'''

	public = True

	def register(self):
		parser = super(Head, self).register()
		parser.add_argument('-n', '--lines', default=10, type=int)

	def __call__(self, args):
		return (args.stdin or [])[:args.lines]


class WC(Command):  # FIXME: conflicts with Lamb3
	'''print newline, word, and byte counts for each file'''

	public = False
	ignore_argument_errors = True

	def register(self):
		parser = super(WC, self).register()
		parser.add_argument('-c', '--bytes', action='store_true', help='print the byte counts')
		parser.add_argument('-m', '--chars', action='store_true', help='print the character counts')
		parser.add_argument('-l', '--lines', action='store_true', help='print the newline counts')
		parser.add_argument('-L', '--max-line-length', action='store_true', help='print the length of the longest line')
		parser.add_argument('-w', '--words', action='store_true', help='print the word counts')

	def __call__(self, args):
		stdin = list(args.stdin or [])

		def wc_l():
			return len(stdin)

		def wc_w():
			return str(len('\n'.join(stdin).split()))

		def wc_c():
			return str(len('\n'.join(stdin)))

		if args.lines:
			return wc_l()
		elif args.bytes or args.chars:
			return wc_c()
		elif args.max_line_length:
			return str(len(max(stdin)))
		elif args.words:
			return wc_w()
		elif stdin:
			return '\t%s\t%s\t%s' % (wc_l(), wc_w(), wc_c())


class Date(Command):
	'''print or set the system date and time'''

	public = True

	def register(self):
		parser = super(Date, self).register()
		parser.add_argument('--tz', dest='timezone')
		parser.add_argument('-d', '--date', default='now', help="display time described by STRING, not 'now'")
		parser.add_argument('-u', '--utc', '--universal', action='store_true', help='print or set Coordinated Universal Time (UTC)')
		parser.add_argument('format', metavar='+FORMAT', nargs='?', help='FORMAT controls the output.')

	def __call__(self, args):
		if args.date == 'now':
			if args.utc or args.timezone:
				date = datetime.datetime.utcnow()
			else:
				date = datetime.datetime.now()
		else:
			import dateparser
			date = dateparser.parse(args.date)
		if args.timezone:
			if args.timezone not in pytz.all_timezones:
				return 'Unknown timezone'
			est = pytz.timezone(args.timezone)
			date = pytz.utc.localize(date)
			date = date.astimezone(est)
		if args.format:
			return date.strftime(args.format)
		return date.strftime("%Y-%m-%d %H:%M:%S")


class Hosts(Command):

	def register(self):
		parser = self.add_command(description='Show which box does what', help='Information about gizmores boxes', public=True)
		parser.add_argument('box')

	def __call__(self, args):
		return {
			'wc0': 'wc0.wechall.net: warchall.net',
			'wc1': 'wc1.wechall.net: spaceone + warchall.gizmore.org + logs.warchall.net',
			'wc2': 'wc2.wechall.net: wechall.net',
			'wc3': 'wc3.wechall.net: irc.wechall.net + Lamb3 + tehbot + some challs',
			'wc4': 'wc4.wechall.net: gizmore + busch-peine + wanda + mp3',
		}.get(args.box.strip(), 'No such box')


class HashFunc(Command):

	threaded = True

	@property
	def hashname(self):
		return self.name[:-len('sum')]

	def register(self):
		parser = self.add_command(help='compute and check %s message digest' % (self.hashname.upper(),), public=True, threaded=True)
		parser.add_argument('-d', '--decrypt', action='store_true')
		parser.add_argument('args', nargs='?', default='')

	def __call__(self, args):
		hashname = self.hashname
		_hashfunc = getattr(hashlib, hashname)
		length = len(_hashfunc('').hexdigest())
		foo = '<span title="decrypted %s hash">' % (hashname,)

		content = '\n'.join(args.stdin) if args.stdin else args.args
		if args.decrypt:
			x = content.strip()
			if len(x) == length:
				c = requests.get('http://hashtoolkit.com/reverse-hash/?hash=%s' % (urllib.quote(x),)).content
				if foo not in c:
					return 'hash not found!'
				plain = c.split(foo, 1)[-1].split('</span>', 1)[0]
				return repr(plain).strip('"\'')
		return _hashfunc(content).hexdigest()


class MD5Sum(HashFunc):
	pass


class Sha1Sum(HashFunc):
	pass


class Sha256Sum(HashFunc):
	pass


class Sha512Sum(HashFunc):
	pass


class Trigger(Command):

	admin = True

	def register(self):
		parser = super(Trigger, self).register()
		parser.add_argument('trigger', nargs='?')

	def __call__(self, args):
		if not args.trigger:
			return 'Trigger is: %r' % (self._commander.trigger)
		self._commander.set_trigger(args.trigger)
		return 'New trigger %r active' % (args.trigger,)


class Say(Command):

	admin = True

	def register(self):
		parser = super(Say, self).register()
		parser.add_argument('channel')
		parser.add_argument('message', nargs='+')

	def __call__(self, args):
		self._commander.fire(PRIVMSG(args.channel, ' '.join(args.message)), args.ircserver.channel)


class Join(Command):

	admin = True

	def register(self):
		parser = super(Join, self).register()
		parser.add_argument('channel')

	def __call__(self, args):
		self._commander.fire(JOIN(args.channel), args.ircserver.channel)


class Part(Command):

	admin = True

	def register(self):
		parser = super(Part, self).register()
		parser.add_argument('channel')

	def __call__(self, args):
		self._commander.fire(PART(args.channel), args.ircserver.channel)


class Nick(Command):

	admin = True

	def register(self):
		parser = super(Nick, self).register()
		parser.add_argument('nick')

	def __call__(self, args):
		self._commander.fire(NICK(args.nick), args.ircserver.channel)


class Usage(Command):

	def register(self):
		parser = self.add_command(help='Print usage for a certain command', public=True)
		parser.add_argument('command', choices=self._commander.commands.keys() + ['help'])

	def __call__(self, args):
		if self._commander.command_allowed(args.command, args.source, args.ircserver):
			return self._commander.commands[args.command].format_usage()


class Help(Command):

	def register(self):
		parser = self.add_command(private=True, public=True)
		parser.add_argument('command', nargs='?', choices=self._commander.commands.keys())

	def __call__(self, args):
		if args.command and self._commander.command_allowed(args.command, args.source, args.ircserver):
			return self._commander.commands[args.command].format_help()
		return self._commander.parser.format_usage()


class Login(Command):

	def register(self):
		self.add_command()

	def __call__(self, args):
		self._commander.fire(PRIVMSG('NickServ', 'STATUS %s' % (args.source[0],)), args.ircserver.channel)


class Reload(Command):

	admin = True

	def register(self):
		parser = super(Reload, self).register()
		parser.add_argument('-c', '--core', action='store_true', default=True)

	def __call__(self, args):
		try:
			commander = self._commander
			commander.reload()
			self._commander = reload(sys.modules[__name__]).Commander(self._commander.parent, channel=self._commander.channel).register(self._commander.parent)
			commander.unregister()
		except Exception as exc:
			print traceback.format_exc()
			return 'Reload failed! %s' % (exc,)
		else:
			return 'Okay, ready to crush tehbot!'


class Restart(Command):

	admin = True

	def register(self):
		parser = super(Restart, self).register()
		parser.add_argument('message', nargs='*')

	def __call__(self, args):
		self._commander.fire(QUIT(' '.join(args.message)), args.ircserver.channel)
		return 'Okay, going to exit!'


class Server(Command):

	admin = True

	def register(self):
		parser = super(Server, self).register()
		sub = parser.add_subparsers()
		connect = sub.add_parser('connect')
		connect.set_defaults(connect=True)
		connect.add_argument('server')

		disconnect = sub.add_parser('disconnect')
		disconnect.set_defaults(connect=False)
		disconnect.add_argument('server')
		disconnect.add_argument('message', nargs='*')

	def __call__(self, args):
		if args.connect:
			self._commander.parent.add_server(args.server)
			return 'Connecting to server'
		else:
			self._commander.parent.remove_server(args.server, *args.message)
			return 'Disconnecting from server'


class Debug(Command):

	admin = True

	def register(self):
		parser = super(Debug, self).register()
		parser.add_argument('-e', '--enable', action='store_true')

	def __call__(self, args):
		if args.enable and not self._commander.debugger:
			self._commander.debugger = Debugger()
			self._commander.debugger.register(self._commander)
			return 'Enabled debugger'
		elif self._commander.debugger:
			self._commander.debugger.unregister()
			return 'Disabled debugger'


class Perms(Command):
	pass


class Commander(BaseComponent):
	"""spaceone IRC bot"""

	def reload(self):
		self.plugins.reimport()

	def __init__(self, bot, *args, **kwargs):
		self.trigger = ' '
		self.debugger = None
		self.parser = ArgumentParser(description=self.__doc__, prog='')
		self.subparsers = self.parser.add_subparsers(title='User commands', description='All available commands', parser_class=ArgumentParser)
		self.commands = {}
		self.authenticated = []
		self.master = {'*': ['spaceone', ]}
		self._master = {'*': []}
		self.ignore = []
		import spacebot.plugins as plugins
		self.plugins = plugins
		super(Commander, self).__init__(bot, *args, **kwargs)
		Worker(channel=self.channel).register(self)

	def add_command(self, cmd, callback, no_args=False, exceptions=(), nargs='+', default=None, public=False, private=False, admin=False, threaded=False, ignore_argument_errors=False, **kwargs):
		self.commands[cmd] = self.subparsers.add_parser(cmd, prog=cmd, **kwargs)
		self.commands[cmd].set_defaults(
			func=callback,
			no_args=no_args,
			exceptions=tuple(exceptions),
			stdin=None,
			source=None,
			parser=None,
			ircserver=None,
			private=private,
			admin=admin,
			public=public,
			threaded=threaded,
			ignore_argument_errors=ignore_argument_errors,
		)
		if no_args:
			self.commands[cmd].add_argument("args", nargs=nargs, default=default)
		return self.commands[cmd]

	def init(self, bot, *args, **kwargs):
		plugins = self.plugins.import_plugins()
		for command in [Server, Reload, Restart, Debug, Date, Grep, Echo, Hosts, Tail, Head, WC, MD5Sum, Sha1Sum, Sha256Sum, Sha512Sum, Trigger, Say, Join, Part, Nick, Login] + plugins + [Usage, Help]:
			command(self).register()
		self.nickserv(bot)

	def set_trigger(self, trigger):
		self.trigger = trigger

	def get_trigger(self, source, server):
		triggers = [self.trigger, '%s: ' % (server.nick,)]
		if source[0] == 'spaceone':
			triggers.insert(1, '.')
		return triggers

	def nickserv(self, bot):
		for server in bot.servers.values():
			masters = self.master.get(server.channel, self.master['*'])
			for master in masters:
				self.fire(PRIVMSG('NickServ', 'STATUS %s' % (master,)), server)

	@handler('notice', channel='*')
	def notice(self, event, source, target, raw):
		server = self.parent.servers[event.channels[0]]
		if raw.startswith('STATUS') and source[0] == 'NickServ':
			user, status = (raw.split() + ['', '', ''])[1:3]
			masters = self.master.get(server.channel, self.master['*'])
			orgmasters = self._master.get(server.channel, self.master['*'])
			if user not in orgmasters:
				return
			if status not in ('3',) and user in masters:
				masters.remove(user)
			if status in ('3',) and user not in masters:
				masters.append(user)

	def _get_master(self, server, org=False):
		master = self._master if org else self.master
		return master.get(server.channel, master['*'])

	@handler('privmsg', channel='*', priority=0.5)
	def privmsg(self, event, source, target, raw):
		server = self.parent.servers[event.channels[0]]
		message = strip(raw, True)
		if source[0] not in ('spaceone',) and target == server.nick:
			self.fire(PRIVMSG('spaceone', '%s wrote: %r' % (source[0], message,)), server.channel)
		destination = source[0] if target == server.nick else target
		dest = destination

		if source[0] in self.ignore:
			return
		if source[0] in self._get_master(server, True) and source[0] not in self._get_master(server):
			self.fire(PRIVMSG('NickServ', 'STATUS %s' % (source[0],)), server.channel)

		messages = message
		for trigger in self.get_trigger(source, server):
			if messages.startswith(trigger):
				messages = messages[len(trigger):]
				break
		else:
			return

		stdout = None
		while messages:
			message, separator, messages = self.pop_next(messages)
			if not message:
				break
			from_stdin, to_stdout = None, None
			if separator in ('<', '<<'):
				from_stdin, separator, messages = self.pop_next(messages)
			elif separator in ('>', '>>'):
				to_stdout, separator, messages = self.pop_next(messages)

			command, args = (message.split(None, 1) + [''])[:2]
			command = command.encode('utf-8')
			try:
				if from_stdin and from_stdin not in ('/dev/stdin'):
					stdout = from_stdin
				if self.commands.get(command) and self.commands[command].get_default('threaded'):
					def execute(*args, **kwargs):
						try:
							return self.execute(*args, **kwargs)
						except:
							return sys.exc_info()
					cmd = task(execute, server, command, args, source, target, dest, stdin=stdout)
				else:
					cmd = Event.create('execute', server, command, args, source, target, dest, stdin=stdout)
				value = (yield self.call(cmd)).value
				try:
					dest, stdout = value
				except ValueError:
					raise value[0], value[1], value[2]
				if to_stdout and to_stdout not in ('/dev/stdout',):
					if not to_stdout.startswith('/') and to_stdout not in ('spaceone',) and source[0] not in ('spaceone'):
						raise ArgumentInfos('Cannot redirect to other users/channels! login or redirect to /foo.')
					elif not to_stdout.startswith('/') and source[0] in ('spaceone'):
						if dest == destination:
							dest = to_stdout
					elif to_stdout in ('spaceone', 'livinskull', 'tehron', 'dloser', '#wechall', '#wechalladmin', '#spaceone'):
						if dest == destination:
							dest = to_stdout
					else:
						stdout = []
				if separator == '||':
					break
				elif separator in ('&&', ';', '&'):
					self.respond(dest, stdout, server)
					dest = destination
					stdout = []
			except ArgumentInfos as exc:
				stdout = str(exc).splitlines()
				if not separator or separator == '&&':
					break
			except ArgumentParserError as exc:
				stdout = ("Error: %s" % (exc)).splitlines()
				if not separator or separator == '&&':
					break
			except BaseException as exc:
				print traceback.format_exc()
				stdout = ("Error: %s" % (exc)).splitlines()
				for line in self.wrap(traceback.format_exception(*sys.exc_info())):
					self.fire(PRIVMSG('spaceone', repr(line).lstrip('u').strip('\'"')), server.channel)
				break
		self.respond(dest, stdout, server)

	def respond(self, dest, stdout, server):
		for line in self.wrap(stdout or []):
			self.fire(PRIVMSG(dest, line), server.channel)

	def pop_next(self, messages):
		separators = ['>>', '&&', '||', '>', '&', '|', '<<', '<', ';']
		index, separator = self.find_next(messages)
		separator = type(messages)(separator)
		if separator:
			message = messages[:index]
			_, separator, messages = messages[index:].partition(separator)
		else:
			message, messages = messages, ''
		for sep in separators:
			message = message.replace('\\%s' % (sep,), sep)
		return message.strip(), separator, messages.strip()

	def find_next(self, messages):
		# TODO: ignore escaped
		separator = ['>>', '&&', '||', '>', '&', '|', '<<', '<', ';']
		results = [(messages.index(sep), sep) for sep in separator if sep in messages]
		results = [(i, sep) for i, sep in results if messages[i - 1:i] != '\\']
		if not results:
			return 0, ''

		minimum = min(results)[0]
		sep = max([x[1] for x in results if x[0] == minimum])
		return minimum, sep

	@handler('execute')
	def execute(self, server, command, args, source, target, dest, stdin=None):
		if command not in self.commands:
			if stdin:
				raise ArgumentInfos('-%s: %r: command not found' % (server.nick, repr(command).strip('u').strip('\'"')))
			return dest, []
		if not self.command_allowed(command, source, server):
			if stdin:
				raise ArgumentInfos('-%s: %r: Permission denied' % (server.nick, repr(command).strip('u').strip('\'"')))
			return dest, []

		parser = self.commands[command]
		if parser.get_default('private'):
			dest = source[0]
		try:
			args = parser.parse_args(args)
		except ArgumentParserError:
			if not parser.get_default('ignore_argument_errors'):
				raise
			return dest, None
		args.parser = parser
		args.ircserver = server
		args.stdin = stdin
		args.source = source
		args.target = target
		try:
			result = args.func(args)
			if isinstance(result, str):
				result = result.decode('utf-8', 'replace')
			if isinstance(result, basestring):
				result = result.splitlines()
			return dest, result
		except args.exceptions as exc:
			return dest, str(exc).decode('utf-8', 'replace').splitlines()

	def command_allowed(self, command, source, server):
		is_admin = source[0] == 'spaceone'
		is_master = source[0] in self._get_master(server)
		needs_master = not self.commands[command].get_default('public')
		needs_admin = self.commands[command].get_default('admin')
		if (needs_master and not is_master) or (needs_admin and not is_admin):
			return False
		return True

	def wrap(self, x, length=400):
		if isinstance(x, (list, tuple)):
			for y in x:
				for _ in self.wrap(y):
					yield _
		elif isinstance(x, (str, bytes, unicode)):
			if isinstance(x, unicode):
				x = x.encode('utf-8', 'replace')
			for _ in textwrap.wrap(str(x), length):
				yield _
		else:
			raise TypeError('Return %r not supported.' % (type(x).__name__,))
