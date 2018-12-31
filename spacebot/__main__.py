from spacebot import SpaceBot
import traceback


if __name__ == "__main__":
	try:
		bot = SpaceBot.main()
	except (SystemExit, KeyboardInterrupt, SyntaxError):
		raise
	except:
		print 'MainError:'
		print traceback.format_exc()
		raise
