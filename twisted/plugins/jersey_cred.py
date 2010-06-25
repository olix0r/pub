from os import geteuid
from time import time

from twisted.application.service import IServiceMaker, MultiService
from twisted.application.internet import TCPServer

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.portal import IRealm, Portal

from twisted.plugin import IPlugin
from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.python.filepath import FilePath
from twisted.python.usage import Options, UsageError

from twisted.web.resource import IResource, Resource
from twisted.web.server import Site

from zope.interface import implements

from jersey.cred.cred import PubKeyCredentialFactory
from jersey.cred.service import IPublicKeyService, DirectoryBackedKeyService
import jersey.cred.ws


WWW_PORT = 80 if geteuid() == 0 else 8080


class User(object):

    def __init__(self, name):
        self.name = name
        self.logins = 0
        self.logouts = 0

    
    def loggedIn(self):
        self.logins += 1

    def loggedOut(self):
        self.logouts += 1



class Realm(object):
    implements(IRealm)

    def __init__(self, keySvc):
        self.keySvc = keySvc
        self.users = dict()


    def requestAvatar(self, avatarId, _mind, *interfaces):
        log.msg("{0} is requesting an avatar.".format(avatarId))
        if IResource in interfaces:
            if avatarId in self.users:
                user = self.users[avatarId]
            else:
                user = self.users[avatarId] = User(avatarId)

            user.loggedIn()
            resource = AuthorizedResource(user)
            return (IResource, resource, user.loggedOut)

        raise NotImplementedError()


registerAdapter(Realm, IPublicKeyService, IRealm)



class AuthorizedResource(Resource):

    def __init__(self, user):
        self.user = user

    def render_GET(self, request):
        return "YAY! YOU FOUND ME\n"



class JerseyKeysOptions(Options):
    optParameters = [
        ["keydir", "K", "keys.pub", "Public key directory"],
        ["port", "p", WWW_PORT, "Port", int],
        ]


    def postOptions(opts):
        opts["keydir"] = kd = FilePath(opts["keydir"])
        if not kd.isdir():
            raise UsageError("{0}: Not a directory".format(kd.path))



class ServiceMaker(object):
    implements(IServiceMaker, IPlugin)

    tapname = "cred.jersey"
    description = "Jersey Public Key Service"
    options = JerseyKeysOptions


    def makeService(self, options):
        svc = MultiService()

        keySvc = DirectoryBackedKeyService(options["keydir"])
        keySvc.setServiceParent(svc)
        
        portal = self.buildPortal(keySvc)
        site = self.buildSite(keySvc, portal)

        www = TCPServer(options["port"], site)
        www.setServiceParent(keySvc)

        return svc


    def buildPortal(self, keyService):
        realm = IRealm(keyService)
        checker = ICredentialsChecker(keyService)
        return Portal(realm, [checker,])


    def buildSite(self, keySvc, portal):
        root = IResource(keySvc)
    
        factories = [
            PubKeyCredentialFactory("users@cred.jersey"),
            ]
        authorized = jersey.cred.ws.JerseyGuard(portal, factories)

        root.putChild("authorisation", authorized)
        root.putChild("authorization", authorized)

        return Site(root)


JerseyKeys = ServiceMaker()


