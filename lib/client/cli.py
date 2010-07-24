
import os, re, sys

#from twisted.application.app import ReactorSelectionMixin
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.protocol import ClientCreator
from twisted.python.filepath import FilePath

from jersey import cli, log

from pub import client, iface, version


UsageError = cli.UsageError

CommandFactory = cli.CommandFactory


class Command(cli.Command):

    def __init__(self, config):
        cli.Command.__init__(self, config)
        self.pub = getattr(config, "pubSvc", None)
        self.pub.setServiceParent(self)


class Options(cli.Options):

    @property
    def pubSvc(self):
        return getattr(self.parent, "pubSvc", None)



class PubClientOptions(cli.PluggableOptions):

    commandPackage = client
    defaultSubCommand = "list-keys"

    optParameters = [
        ["server", "s", os.getenv("PUB_URL"), "Pub Service URI"],
        ["auth-sock", "A", os.getenv("PUB_AUTH_SOCK"), "Authentication agent socket"],
        ["auth-conf", "A", os.getenv("PUB_AUTH_CONF", "~/.pub.auth.conf"),
            "Authentication agent socket"],
        ]

    optFlags = [
        ["debug", "D", "Print debugging output"],
        ]


    def opt_version(self):
        try:
            super(PubClientOptions, self).opt_version()
        except SystemExit:
            pass
        print "Pub version: " + version.short()
        raise SystemExit(0)

    opt_V = lambda s: s.opt_version()


    @staticmethod
    def _toUrl(url):
        if not url:
            raise cli.UsageError("No Pub server")
        from twisted.python.urlpath import URLPath
        try:
            return URLPath.fromString(url)
        except:
            raise cli.UsageError("Invalid URL: {0}".format(url))


    def postOptions(self):
        if self["debug"]:
            self.logLevel = log.DEBUG

        self["server"] = self._toUrl(self["server"])
        self.pubSvc = self.buildPubService()

        self["auth-conf"] = FilePath(os.path.expanduser(self["auth-conf"]))


    _commentPfx = "#"

    def readAuthConfig(self):
        """
        An Auth config is in the format::
        
          # Commentary
          <key-id>  [id:][range(re)?@](?:.+\.)?domain\.re [id:](?:+\.)otherdom\.re
          <key-id>  [id:][range@]host\.yaodom\.re
          <okey-id> [range@]host\.yaodom\.re
        """
        config = {}
        if self["auth-conf"].exists():
            with self["auth-conf"].open() as ac:
                for line in ac:
                    line = line.strip()
                    if line and not line.startswith(self._commentPfx):
                        try:
                            keyId, matchSpec = line.split(None, 1)
                            matches = self._parseMatchSpec(matchSpec)
                            config.setdefault(keyId, []).extend(matches)
                        except:
                            log.err()
        return config


    _userDelim = ":"

    def _parseMatchSpec(self, matchSpec):
        """
        Parse a list of (user, regex) tuples from text in the format::

          [id@](?:.+\.)?domain\.re [id@](?:+\.)otherdom\.re
        """
        matches = []
        for spec in matchSpec.split():
            if self._userDelim in spec:
                user, spec = spec.split(self._userDelim, 1)
            else:
                user = None
            if spec:
                realmRE = re.compile(spec, re.I)
            else:
                realmRE = None
            matches.append((user, realmRE))
        return matches


    def buildPubService(self):
        url = self["server"]
        if url.scheme.lower() == "sqlite3":
            if url.netloc:
                raise cli.UsageError(
                        "Local scheme with remote location: {0}".format(url))
            from pub import db
            dbx = db.connectDB("sqlite3", url.path)
            svc = db.PubService(dbx)

        elif url.scheme.lower() in ("http", "https"):
            authAgent = self.buildAuthAgent()
            webAgent = self.buildWebAgent()

        else:
            raise cli.UsageError("Unsupported scheme: {0}".format(url))

        return svc


    def buildWebAgent(self):
        from pendrell import Agent
        return Agent(authenticators=auths)



class PubClientRunner(cli.PluggableCommandRunner):
    pass



def run(args=sys.argv[:]):
    """Run with command line arguments (including argv[0])"""
    binDir, progName = os.path.split(args.pop(0))

    config = PubClientOptions(progName)
    try:
        config.parseOptions()

        runner = PubClientRunner(progName, config)
        runner.run()

    except cli.UsageError, ue:
        print >>sys.stderr, config.getUsage()
        print >>sys.stderr, str(ue)
        raise SystemExit(os.EX_USAGE)

    else:
        raise SystemExit(runner.exitValue)

