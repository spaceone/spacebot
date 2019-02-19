# -*- coding: utf-8 -*-

import re

from spacebot.plugins import Command
from circuits import BaseComponent, handler
from circuits.protocols.irc import PRIVMSG


class WeChallCommands(BaseComponent):

	WC = re.compile(r'''^(?:ok|okay|hey)\s+(?P<bot>\w*),?\s*(?:has|did)\s+(?P<who>\w+)\s+solved?\s+(?P<chall>\w[\s\w]*?|"[^"]+"|'[^']+')(?:\s+on\s+(?P<site>\w[\s\w]*?|"[^"]+"|'[^']+'))?\s*\??$''', re.I)

	@handler('privmsg', channel='*', priority=0.6)
	def _okay_privmsg(self, event, source, target, message):
		match = self.WC.search(message)
		if not match:
			return

		server = self.parent.parent.servers[event.channels[0]]
		dest = source[0] if target == server.nick else target
		event.stop()
		user = match.group(1)
		chall = match.group(2)
		site = match.group(3) or 'wc'
		if site.lower() in ('wc', 'wechall') and match.group('bot') != 'tehbot':
			part = solvers(chall, user=user)
			self.fire(PRIVMSG(dest, part), server.channel)


class WeChall(Command):

	def register(self):
		super(WeChall, self).register()
		if hasattr(self._commander, 'wechall'):
			self._commander.wechall.unregister()
		self._commander.wechall = WeChallCommands(channel=self._commander.channel).register(self._commander)
