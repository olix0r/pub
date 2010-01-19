from time import time

from twisted.application.service import IServiceMaker, MultiService
from twisted.application.internet import TCPServer

from twisted.cred.portal import IRealm, Portal

from twisted.plugin import IPlugin
from twisted.python.components import registerAdapter
from twisted.python.filepath import FilePath
from twisted.python.usage import Options

from twisted.web.resource import IResource, Resource
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.server import Site

from zope.interface import implements

from jersey.auth.cred import JerseyCredentialFactory
from jersey.auth.service import IPublicKeyService, DirectoryBackedKeyService
import jersey.auth.ws



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
        if IResource in interfaces:
            if avatarId in users:
                user = self.users[avatarId]
            else:
                user = self.users[avatarId] = User(avatarId)

            user.loggedIn()
            resource = AuthorizedResource(user)
            return (IResource, resource, user.loggedOut)

        raise NotImplementedError()


registerAdapter(IPublicKeyService, IRealm, Realm)



class AuthorizedResource(Resource):

    def __init__(self, user):
        self.user = user

    def render(self, request):
        pass



class JerseyKeysOptions(Options):

    optParameters = [
        ["keydir", "K", "Public key directory", "keys.pub", FilePath],
        ["port", "p", "Port", 8080, int],
        ]



class ServiceMaker(object):
    implements(IServiceMaker, IPlugin)

    tapname = "jersey-keys"
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
    
        authorized = HTTPAuthSessionWrapper(portal, [c,])
        root.putChild("authorisation", authorized)
        root.putChild("authorization", authorized)

        return Site(root)


serviceMaker = ServiceMaker()


