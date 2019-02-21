#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from socket import gethostname
import signal
import argparse
import urlparse

from circuits import handler, Component, BaseComponent, Debugger, Event, sleep

#from circuits.io import stdin

from circuits.net.events import connect, write
from circuits.net.sockets import TCPClient

from circuits.protocols.irc import IRC, USER, NICK, JOIN, QUIT
from circuits.protocols.irc.utils import irc_color_to_ansi
from circuits.protocols.irc.numerics import RPL_WELCOME, ERR_USERONCHANNEL

from spacebot.cmds import Commander


class SpaceBotClient(Component):

	channel = "ircclient"

	def init(self, host, port=None, secure=False, nick=None, ircchannels=None, channel=channel):
		self.host = host
		self.port = port or 6667
		self.hostname = gethostname()

		self.nick = nick
		self.ircchannel = ircchannels

		TCPClient(secure=secure, channel=self.channel).register(self)
		self.irc = IRC(channel=self.channel).register(self)

		self.last_called = 0
		self.max_rate = 1
		self.privmsg_queue = []

	def ready(self, component):
		self.fire(connect(self.host, self.port))

	def connected(self, host, port):
		print("Connected to %s:%d" % (host, port))

		nick = self.nick
		hostname = 'wc3.wechall.net:61221'
		# hostname = gethostname()
		name = "%s!spacebot (%s)" % (nick, hostname)

		self.fire(NICK(nick))
		self.fire(USER(nick, nick, hostname, name))

	def disconnected(self):
		print("Disconnected from %s:%d" % (self.host, self.port))
		self.unregister()

	def numeric(self, source, numeric, *args):
		if numeric == RPL_WELCOME:
			for channel in self.ircchannel:
				self.fire(JOIN(channel))
		elif numeric == ERR_USERONCHANNEL:
			self.nick = newnick = "%s_" % self.nick
			self.fire(NICK(newnick))

	def join(self, source, channel):
		if source[0].lower() == self.nick.lower():
			print("Joined %s" % channel)
		else:
			print("--> %s (%s) has joined %s" % (source[0], "@".join(source[1:]), channel))

	def notice(self, source, target, message):
		print("<%s> -> <%s> Notice - %s" % (source[0], target, irc_color_to_ansi(message)))

	@handler('privmsg', priority=1.0)
	def privmsg(self, event, source, target, message):
		print("<%s> -> <%s> %s" % (source[0], target, irc_color_to_ansi(message)))

		if source[0] == self.nick:
			event.stop()  # prevent recursion
			return

	@handler('request', priority=1.0)
	def request(self, event, message):
		event.stop()
		if message.command == "PRIVMSG":
			if not self.privmsg_queue:
				self.fire(Event.create('privmsg_queue'))
			self.privmsg_queue.append(message)
			return
		self.last_called = time.time()
		message.encoding = self.irc.encoding
		self.fire(write(bytes(message)))

	@handler('privmsg_queue')
	def _privmsg_queue(self):
		while self.privmsg_queue:
			message = self.privmsg_queue.pop(0)
			message.encoding = self.irc.encoding
			self.last_called = time.time()
			self.fire(write(bytes(message)))
			elapsed = time.time() - self.last_called
			must_wait = 1 / self.max_rate - elapsed
			if must_wait > 0:
				yield sleep(max(0, must_wait))

	@handler("read", channel="stdin")
	def stdin_read(self, data):
		data = data.strip().decode("utf-8")

		print("<{0:s}> {1:s}".format(self.nick, data))


class SpaceBot(BaseComponent):

	channel = 'ircconnections'

	@classmethod
	def main(cls, args=None):
		try:
			import setproctitle
			setproctitle.setproctitle('spaceonebot')
		except ImportError:
			pass
		parser = argparse.ArgumentParser(prog='spaceonebot')

		parser.add_argument("-s", "--server", action="append", help="URI of a server, e.g. ircs://spacebot@irc.freenode.net:6697/#channel")
		parser.add_argument("--without-stdin", action="store_true", help="Disable stdin commands")
		parser.add_argument("--without-readline", action="store_false", default=False, help="Disable readline prompt and tab completion")
		parser.add_argument("-d", "--debug", action="store_true", default=False, help="Enable debug verbose logging")

		args = parser.parse_args(args)
		conn = cls(args)
		if args.debug:
			Debugger().register(conn)
		conn.run()
		#if args.without_readline:
		#	stdin.register(client)
		# readline.parse_and_bind("tab: complete")
		# client.start()
		# time.sleep(0.3)
		# while client.running:
		# 	client.stdin_read(raw_input('>>> '))
		return conn

	def __init__(self, args):
		super(SpaceBot, self).__init__()
		self.servers = {}
		for server in args.server:
			self.add_server(server)
		self.commander = Commander(self, channel=self.channel).register(self)

	def add_server(self, server):
		server = urlparse.urlparse(server)
		print('Adding server: %r' % (server,))
		channels = ('#' + server.fragment).split(',') if server.fragment else []
		client = SpaceBotClient(server.hostname, server.port, server.scheme == 'ircs', nick=server.username, ircchannels=channels, channel=server.hostname).register(self)
		self.servers[client.channel] = client
		return client

	def remove_server(self, server, message='Leaving!'):
		for client in self.servers.values():
			if client.channel == server:
				client.fire(QUIT(message))
				return client

	def disconnect(self, message='Leaving!'):
		for server in self.servers:
			self.remove_server(server, message)

	@handler('unregistered', channel='*')
	def unregistered(self, child, parent):
		if parent is self and child in self.servers.values():
			self.servers.pop(child.channel)
		if not self.servers:
			self.stop()

	@handler('signal')
	def signal(self, event, signo, stack):
		if signo == signal.SIGINT:
			for client in self.servers.values():
				client.fire(QUIT('Keyboard interrupt'))
