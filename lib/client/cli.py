
import os, sys

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
        ["server", "s", os.getenv("PUB_URL"), "Pub service URI"],
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


    def buildPubService(self):
        url = self["server"]
        if not url:
            raise cli.UsageError("No Pub server")

        if url.scheme.lower() == "sqlite3":
            if url.netloc:
                raise cli.UsageError(
                        "Local scheme with remote location: {0}".format(url))
            from pub import db
            dbx = db.connectDB("sqlite3", url.path)
            svc = db.PubService(dbx)

        else:
            raise cli.UsageError("Unsupported scheme: {0}".format(url))

        return svc



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

