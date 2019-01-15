# -*- coding: utf-8 -*-

import inspect
import pkgutil
import importlib

from spacebot.cmds import Command

__all__ = ('Command', 'import_plugins', 'reimport')

commands = []


def reimport():
	return
	import spacebot.plugins
	reload(spacebot.plugins)


def is_command(member):
	return inspect.isclass(member) and member is not Command and len(member.mro()) > 2


def import_plugins():
	del commands[:]
	for importer, module, ispkg in pkgutil.walk_packages(path=__path__, prefix=__name__ + '.'):
		print 'Importing ', module, ispkg
		try:
			commands.append(importlib.import_module(module, __name__))
		except ImportError as exc:
			print 'Could not import module', module, str(exc)

	plugins = []
	for c in commands:
		plugins.extend(dict(inspect.getmembers(c, is_command)).values())
	print 'Registering plugins', plugins
	return plugins
