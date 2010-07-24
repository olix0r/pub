
import json, os, re, sys

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
        if self.pub:
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
        ["auth-conf", "a", os.getenv("PUB_AUTH_CONF", "~/.pub.auth.conf"),
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
    def _toUrl(spec):
        if not spec:
            raise cli.UsageError("No Pub server")
        from twisted.python.urlpath import URLPath
        try:
            url = URLPath.fromString(spec)
        except:
            raise cli.UsageError("Invalid URL: {0}".format(spec))
        if not spec.startswith(url.scheme):
            raise cli.UsageError("Invalid URL: {0}".format(spec))
        return url


    def postOptions(self):
        if self["debug"]:
            self.logLevel = log.DEBUG

        self["server"] = self._toUrl(self["server"])
        self["auth-conf"] = FilePath(os.path.expanduser(self["auth-conf"]))
        if self["auth-sock"]:
            self["auth-sock"] = FilePath(os.path.expanduser(self["auth-sock"]))

        self.pubSvc = self.buildPubService()


    def buildPubService(self):
        url = self["server"]
        log.debug("Building PubService({0})".format(url))

        # TODO (Jersey) Plugins?
        pubBuilders = {
                "http": self._buildPubService_http,
                "https": self._buildPubService_http,
                "sqlite3": self._buildPubService_sqlite3,
                }
        scheme = url.scheme.lower()
        buildService = pubBuilders.get(scheme)

        if buildService is None:
            raise cli.UsageError("Unsupported scheme: {0}".format(url))
        return buildService(url)


    def _buildPubService_sqlite3(self, url):
        if url.netloc:
            raise cli.UsageError("Invalid URL: {0}".format(url))
        from pub import db
        dbx = db.connectDB("sqlite3", url.path)
        svc = db.PubService(dbx)
        return svc


    def _buildPubService_http(self, url):
        if not url.netloc:
            raise cli.UsageError("Invalid URL: {0}".format(url))
        from pub.client import ws
        self.authenticator = self._buildAuthService()
        self.agent = self._buildWebAgent()
        svc = ws.PubService(self)
        return svc


    def _buildAuthService(self):
        if self["auth-sock"] and self["auth-sock"].exists():
            from pub.client.auth import AuthService, SSHAgentClient
            auths = self.readAuthConfig(self["auth-conf"])
            svc = AuthService(auths)
            svc.attachSocket(self["auth-sock"].path)

        else:
            svc = None

        return svc


    def _buildWebAgent(self):
        from pub.client.ws import PubAgent
        return PubAgent()


    _commentPfx = "#"

    def readAuthConfig(self, path):
        """
        An Auth config is in the format::
        
          # Commentary
          {"authenticators": [
           {"keyId": keyId, "realms":[{"id":userId, "realm":realmRegex}]}
           ]
          }
        """
        if path and path.exists():
            try:
                stripped = self._stripFile(path)
                config = json.loads(stripped)
                authenticators = config["authenticators"]

            except Exception, e:
                msg = "Malformed configuration: {0!s}".format(e)
                if "stripped" in locals():
                    msg += "\n" + stripped
                raise UsageError(msg)

        else:
            authenticators = []

        return self._compileRealmRegexes(authenticators)


    def _stripFile(self, path):
        stripped = ""
        with path.open() as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(self._commentPfx):
                    stripped += line
        return stripped


    def _compileRealmRegexes(self, authenticators):
        # Need to use a copy of the list if we need to remove() items.
        for authSpec in list(authenticators):
            try:
                if "realms" in authSpec:
                    for realmSpec in authSpec["realms"]:
                        if "realm" in realmSpec:
                            realmSpec["pattern"] = pattern = realmSpec["realm"]
                            realmSpec["realm"] = re.compile(pattern)

            except:
                authenticators.remove(authSpec)
                log.err()

        return authenticators


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
        print >>sys.stderr, str(config)
        print >>sys.stderr, str(ue)
        raise SystemExit(os.EX_USAGE)

    else:
        raise SystemExit(runner.exitValue)

