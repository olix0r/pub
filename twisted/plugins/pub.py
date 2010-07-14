from os import geteuid
from time import time

from twisted.application.service import IServiceMaker, MultiService
from twisted.application.internet import TCPServer
from twisted.cred import checkers, portal
from twisted.plugin import IPlugin
from twisted.python.components import registerAdapter
from twisted.python.filepath import FilePath
from twisted.python.usage import Options, UsageError

from twisted.web.resource import IResource, Resource
from twisted.web.server import Site

from zope.interface import implements

from jersey import log
from jersey.cred.pub import db as pubdb, ws
from jersey.cred.pub.guard import Guard, PubKeyCredentialFactory
from jersey.cred.pub.iface import IPubService



_WWW_PORT = 80 if geteuid() == 0 else 8080
_MIN_PORT = 1
_MAX_PORT = 2 ** 16 - 1

def _toPort(port):
    try:
        port = int(port)
    except ValueError:
        raise UsageError("invalid port: {0}".format(port))
    else:
        if not (_MIN_PORT <= port <= _MAX_PORT):
            raise UsageError("Invalid port number: {0}".format(port))
    return port



class PubOptions(Options):

    optParameters = [
        ["www-port", "p", _WWW_PORT, "Web Service Port", _toPort],
        ]

    synopsis = "[options] db-path"

    def parseArgs(self, dbPath):
        self["db-path"] = dbPath



class ServiceMaker(object):
    implements(IServiceMaker, IPlugin)

    tapname = "pub"
    description = "Pub Key Service"
    options = PubOptions

    credFactories = [
        PubKeyCredentialFactory("users@pub"),
        ]

    def makeService(self, opts):
        db = self.connectDB(opts)
        svc = pubdb.PubService(db)
        loginPortal = self.buildPortal(svc, opts)
        self.connectWWW(svc, loginPortal, opts)
        return svc


    def connectDB(self, opts):
        return pubdb.connectDB("sqlite3", opts["db-path"])


    def buildPortal(self, svc, opts):
        return portal.Portal(portal.IRealm(svc), [
                checkers.ICredentialsChecker(svc),
                ])


    def connectWWW(self, svc, loginPortal, opts):
        site = self.buildSite(svc, loginPortal, opts)
        www = TCPServer(opts["www-port"], site)
        www.setServiceParent(svc)
        return www

    def buildSite(self, svc, loginPortal, opts):
        return Site(Guard(loginPortal, self.credFactories))



PubMaker = ServiceMaker()



class PubRealm(object):
    implements(portal.IRealm)

    class avatarClass(object):

        def __init__(self, avatarId):
            self.id = avatarId
            self.logins = 0
            self.logouts = 0
        
        def loggedIn(self):
            self.logins += 1

        def loggedOut(self):
            self.logouts += 1


    def __init__(self, pubSvc):
        self.pubSvc = pubSvc
        self._seen = dict()

    def requestAvatar(self, avatarId, _mind, *interfaces):
        log.msg("{0} is requesting an avatar for {1}.".format(avatarId,
                " or ".join(i.__name__ for i in interfaces)))
        if IResource in interfaces:
            if avatarId in self._seen:
                a = self._seen[avatarId]
            else:
                a = self._seen[avatarId] = self.avatarClass(avatarId)
            a.loggedIn()

            interface = IResource
            avatar = AuthorizedPubResource(a, IResource(self.pubSvc))
            logOut = a.loggedOut

        else:
            raise NotImplemented(interfaces)

        log.debug("Avatar: {0!r} {1!r}".format(interface.__name__, avatar.id))
        return (interface, avatar, logOut)


registerAdapter(PubRealm, IPubService, portal.IRealm)



class AuthorizedPubResource(Resource):

    def __init__(self, avatar, root):
        Resource.__init__(self)
        self.avatar = avatar
        self.root = root

    @property
    def id(self):
        return self.avatar.id

    def getChildWithDefault(self, name, request):
        log.debug("Getting authorized child: {0!r} from {1!r}".format(name,
            self.root))
        return self.root.getChildWithDefault(name, request)

    def render(self, request):
        log.debug("Rendering authorized root: {0!r}".format(self.root))
        return self.root.render(request)



