# -*- coding: utf-8 -*-

import sys
import inspect
import pkgutil
import importlib

from spacebot.cmds import Command, ArgumentInfos

__all__ = ('Command', 'ArgumentInfos', 'import_plugins', 'reimport')

commands = []


def reimport():
	for module in [x for x in sys.modules if x == __name__ or x.startswith(__name__ + '.')]:
		sys.modules.pop(module)
	return
	import spacebot.plugins
	reload(spacebot.plugins)


def is_command(member):
	return inspect.isclass(member) and member is not Command and len(member.mro()) > 2 and issubclass(member, Command)


def import_plugins():
	del commands[:]
	for importer, module, ispkg in pkgutil.walk_packages(path=__path__, prefix=__name__ + '.'):
		print 'Importing', module
		try:
			commands.append(importlib.import_module(module, __name__))
		except ImportError as exc:
			print 'Could not import module', module, str(exc)

	plugins = []
	for c in commands:
		plugins.extend(dict(inspect.getmembers(c, is_command)).values())
	print 'Registering plugins:\n', '\n'.join(map(repr, plugins))
	return plugins
