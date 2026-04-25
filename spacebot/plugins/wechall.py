import functools
import re
import requests
from urllib.parse import urljoin, quote, urlencode
import lxml.html
import traceback

from spacebot.plugins import Command
from circuits import BaseComponent, handler
from circuits.protocols.irc import PRIVMSG

profileurl = 'https://www.wechall.net/profile/%s'
url2 = 'https://www.wechall.net/wechallchalls.php?%s'
challurl = 'https://www.wechall.net/index.php?mo=WeChall&me=Challs&all=1&ajax=1'
rankurl = 'https://www.wechall.net/index.php?mo=WeChall&me=SiteRankings&sid=1&ajax=1&page=%d'
solversurl = 'https://www.wechall.net/index.php?mo=WeChall&me=SolvedBy&cid=%d&page=%d&ajax=1'
prefix = ''  # \x0303[WeChall]\x03 "


class WeChallCommands(BaseComponent):
    WC = re.compile(
        r"""^(?:ok|okay|hey)\s+(?P<bot>\w*),?\s*(?:has|did)\s+(?P<who>\w+)\s+solved?\s+(?P<chall>\w[\s\w]*?|"[^"]+"|'[^']+')(?:\s+on\s+(?P<site>\w[\s\w]*?|"[^"]+"|'[^']+'))?\s*\??$""",
        re.I,
    )

    @handler('privmsg', channel='*', priority=0.6)
    def _okay_privmsg(self, event, source, target, message):
        match = self.WC.search(message)
        if not match:
            return

        server = self.parent.parent.servers[event.channels[0]]
        dest = source[0] if target == server.nick else target
        event.stop()
        user = match.group('who')
        chall = match.group('chall')
        site = match.group('site') or 'wc'
        if site.lower() in ('wc', 'wechall'):  # and match.group('bot') != 'tehbot':
            part = WCC.solvers(chall, user=user)
            self.fire(PRIVMSG(dest, part), server.channel)


class Solvers(Command):
    def register(self):
        parser = super().register()
        parser.add_argument('challenge')

    def __call__(self, args):
        challenge = '\n'.join(args.stdin) if args.stdin else args.challenge
        return WCC.solvers(challenge)


class WCC(Command):
    """Query wechall for progress on wechall."""

    def register(self):
        parser = super().register()
        parser.add_argument('user', nargs='?')

        if hasattr(self._commander, 'wechall'):
            self._commander.wechall.unregister()
        self._commander.wechall = WeChallCommands(channel=self._commander.channel).register(self._commander)

    def __call__(self, args):
        user = '\n'.join(args.stdin) if args.stdin else args.user
        source = args.source[0]
        user = user or source

        if user.isdigit():
            rank = int(user)
            user = WCC.rankstats(rank) or user

        stats = WCC.userstats(user)
        if not stats:
            return f'{source}: The user does not exist.'
        (
            real_user,
            challs_solved,
            challs_total,
            rank,
            _users_total,
            score,
            scoremax,
        ) = stats
        return f'{source}: {real_user} solved {challs_solved} of {challs_total} Challenges with {score} of {scoremax} possible points ({(100 / scoremax * score):.2f}%). Rank for the site WeChall: {rank}'

    @staticmethod
    def parse_html(url):
        parser = lxml.html.HTMLParser(
            no_network=True,
            recover=True,
        )
        return lxml.html.fromstring(requests.get(url).content, parser=parser)

    @staticmethod
    def user_solved(user, nr, name):
        try:
            tree = WCC.parse_html(profileurl % quote(user))
        except Exception:
            print(traceback.format_exc())
            return False, True

        for row in tree.xpath("//div[@id='page']/table[@id='wc_profile_challenges']//tr"):
            e = row.xpath('td[2]/a[1]')
            if e:
                n = e[0].text_content()
                if n.lower().startswith(name.lower()):
                    e2 = e[0].xpath('@class')
                    return e2 and e2[0] == 'wc_chall_solved_1', False

        return False, False

    @staticmethod
    def solvers(challenge_name_or_nr, user=None):
        nr, name, _url, solvers = WCC.find_chall(challenge_name_or_nr)
        if solvers is None:
            WCC.parse_challs.cache_clear()
            nr, name, _url, solvers = WCC.find_chall(challenge_name_or_nr)

        txt = 'Unknown challenge.'
        if solvers is not None:
            if user:
                solved, err = WCC.user_solved(user, nr, name)
                if err:
                    return prefix + 'Error'
                txt = 'Challenge Nr. %d, %s, has %sbeen solved by %s.' % (
                    nr,
                    name,
                    '' if solved else 'not ',
                    user,
                )
                txt += ' Last by %s.' % ', '.join(WCC.get_last_solvers(nr))
            else:
                txt = "Challenge Nr. %d, %s, hasn't been solved by anyone yet." % (nr, name)

                if solvers > 0:
                    txt = 'Challenge Nr. %d, %s, has been solved by %d user%s.' % (
                        nr,
                        name,
                        solvers,
                        '' if solvers == 1 else 's',
                    )

        return prefix + txt

    @staticmethod
    def find_chall(challenge_name_or_nr):
        challs = WCC.parse_challs(challurl)
        nr, name, url, solvers = None, None, None, None

        if isinstance(challenge_name_or_nr, int):
            if challenge_name_or_nr in challs:
                nr = challenge_name_or_nr
                name, url, solvers = challs[challenge_name_or_nr]
        else:
            for key, val in challs.items():
                if val[0].lower().startswith(challenge_name_or_nr.lower()):
                    nr = key
                    name, url, solvers = val
                    break
                if challenge_name_or_nr.lower() in val[0].lower():
                    nr = key
                    name, url, solvers = val
        return nr, name, url, solvers

    @staticmethod
    @functools.lru_cache
    def parse_challs(url):
        challs = {}
        tree = WCC.parse_html(url)
        for e in tree.xpath("//table[@class='wc_chall_table']/tr"):
            e2 = e.xpath('td[2]/a[1]')
            if not e2:
                continue
            name = e2[0].text_content().strip()
            e2 = e.xpath('td[3]/a')
            if not e2:
                continue
            solvers = int(e2[0].text_content().strip())
            e2 = e.xpath('td[3]/a/@href')
            if not e2:
                continue
            match = re.search(r'challenge_solvers_for/(\d+)/', e2[0])
            if not match:
                continue
            nr = int(match.group(1))
            challs[nr] = (name, urljoin(url, e2[0]), solvers)

        return challs

    @staticmethod
    def get_last_solvers(nr):
        url = solversurl % (nr, 1)
        tree = WCC.parse_html(url)
        pages = tree.xpath("//div[@id='page']/div[@class='gwf_pagemenu']//a")
        solvers = []

        if not pages:
            for row in tree.xpath("//div[@id='page']/table//tr"):
                e = row.xpath('td[2]/a[1]')
                if e:
                    n = e[0].text_content()
                    solvers.append(n)
        else:
            lastpage = int(pages[-1].text_content())
            for p in [lastpage - 1, lastpage]:
                url = solversurl % (nr, p)
                tree = WCC.parse_html(url)

                for row in tree.xpath("//div[@id='page']/table//tr"):
                    e = row.xpath('td[2]/a[1]')
                    if e:
                        n = e[0].text_content()
                        solvers.append(n)

        return solvers[::-1][:5]

    @staticmethod
    def rankstats(rank):
        page = 1 + (rank - 1) // 50

        if page < 1:
            return None

        tree = WCC.parse_html(rankurl % page)

        for row in tree.xpath("//div[@id='page']/div[@class='gwf_table']/table//tr"):
            r = row.xpath('td[1]')
            n = row.xpath('td[3]')

            if not r or not n:
                continue

            if int(r[0].text_content()) == rank:
                return n[0].text_content()
                # res = WCC.userstats(n[0].text_content())
                # real_user, challs_solved, challs_total, rank, users_total, score, score_max = res
                # return challs_solved, [real_user], challs_total

        return None

    @staticmethod
    def userstats(user):
        page = requests.get(url2 % urlencode({'username': user})).content.decode('UTF-8', 'ignore')

        match = re.search(
            r'(\w+) solved (\d+) of (\d+) Challenges with (\d+) of (\d+) possible points \(\d+\.\d\d%\). Rank for the site WeChall: (\d+)',
            page,
        )
        if not match:
            return None

        # tree = WCC.parse_html(profileurl % urllib.parse.quote_plus(user))
        # users_total = int(tree.xpath("//div[@id='wc_sidebar']//div[@class='wc_side_content']//div/a[@href='/users']")[0].text_content().split()[0])
        users_total = -1

        real_user, challs_solved, challs_total, score, scoremax, rank = match.groups()
        return (
            real_user,
            str(int(challs_solved)),
            int(challs_total),
            str(int(rank)),
            int(users_total),
            int(score),
            int(scoremax),
        )
