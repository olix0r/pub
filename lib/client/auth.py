"""
PubKey.v1 Client Authenticator module
"""

import os

from twisted.application.internet import UNIXClient
from twisted.application.service import MultiService, Service
from twisted.conch.ssh.agent import SSHAgentClient as _SSHAgentClient
from twisted.internet.defer import (Deferred, inlineCallbacks, returnValue,
        maybeDeferred, succeed)
from twisted.internet.protocol import ClientFactory

from zope.interface import implements

from jersey import log

from pendrell.auth import IAuthenticator

from pub.crypto import Key



class SSHAgentClient(_SSHAgentClient, object):

    def connectionMade(self):
        log.debug("Connected to SSH Agent.")
        super(SSHAgentClient, self).connectionMade()
        self.svc.agentAttached(self)

    def connectionLost(self, reason):
        log.debug("Lost connection to SSH Agent: {0}".format(reason))
        self.svc.agentDetached(self, reason)
        super(SSHAgentClient, self).connectionLost(reason)


class SSHAgentSocketFactory(ClientFactory, object):

    protocol = SSHAgentClient

    def __init__(self, svc):
        super(SSHAgentSocketFactory, self).__init__()
        self.svc = svc

    def buildProtocol(self, addr):
        log.debug("Attaching to SSH Agent on {0}".format(addr))
        p = super(SSHAgentSocketFactory, self).buildProtocol(addr)
        p.svc = self.svc
        return p


class SSHAgentClientService(UNIXClient, object):

    def __init__(self, path, svc, *args, **kw):
        f = SSHAgentSocketFactory(svc)
        super(SSHAgentClientService, self).__init__(path, f, *args, **kw)


class AuthService(MultiService, object):

    def __init__(self, authConfig):
        super(AuthService, self).__init__()
        self.agents = []
        self.keys = {}
        self.authConfig = authConfig
        self._waiting = None


    def __repr__(self):
        return "{0.__class__.__name__}({0.authConfig!r})".format(self)


    @inlineCallbacks
    def startService(self):
        klass = self.__class__.__name__
        log.debug("Starting: {0}".format(self))
        self._waiting = Deferred()
        Service.startService(self)
        i = 0
        for svc in self:
            i += 1
            log.debug("{0} starting [{2}]: {1.__class__.__name__}".format(
                    klass, svc, i))
            yield maybeDeferred(svc.startService)
        log.debug("{0} waiting for agents".format(klass))
        yield self._waiting
        log.debug("{0} loading keys".format(klass))
        yield self.loadKeys()


    def attachSocket(self, path):
        log.debug("Building SSHAgentClientService({0}, {1})".format(path, self))
        socket = SSHAgentClientService(path, self)
        socket.setServiceParent(self)

    def agentAttached(self, agent):
        log.debug("Attached to SSH agent: {0}".format(agent))
        self.agents.append(agent)
        if self._waiting:
            self._waiting.callback(self)
            self._waiting = None

    def agentDetached(self, agent, reason):
        log.debug("Detached from SSH agent: {0}".format(agent))
        try:
            self.agents.remove(agent)
        except:
            log.err()
        self._pruneAgentKeys(agent)


    def _pruneAgentKeys(self, agent):
        for key in self.keys.values():
            if key.agent == agent:
                del self.keys[key.id]


    def signData(self, keyId, data):
        key = self.keys[keyId]
        return key.agent.signData(key.blob(), data)
        

    @inlineCallbacks
    def loadKeys(self):
        log.debug("Loading keys from auth {0} agents".format(len(self.agents)))
        keys = {}
        for agent in self.agents:
            log.debug("Requesting keys from {0}".format(agent))
            rawKeys = yield agent.requestIdentities()
            log.debug("Loaded {0} keys from {1}".format(len(rawKeys), agent))
            for blob, comment in rawKeys:
                k = Key.fromString(blob)
                k.comment = comment
                k.agent = agent
                keys[k.id] = k
        log.debug("Loaded {0} keys from {1} agents".format(
                len(keys), len(self.agents)))
        self._updateKeys(keys)
        returnValue(keys)


    def _updateKeys(self, keys):
        for k in self.keys.keys():
            del self.keys[k]
        self.keys.update(keys)


    def buildAuthenticators(self):
        authenticators = []
        if self.authConfig:
            for authSpec in self.authConfig:
                if authSpec["keyId"] in self.keys:
                    auth = self.buildAuthenticator(authSpec)
                    authenticators.append(auth)
        else:
            for keyId in self.keys:
                auth = self.buildAuthenticator(keyId)
                authenticators.append(auth)
        return authenticators


    def buildAuthenticator(self, authSpec):
        return PubKeyAuthenticator(self, self.keys[authSpec["keyId"]],
                realms=authSpec.get("realms"))



class PubKeyAuthenticator(object):
    implements(IAuthenticator)

    schemes = ("PubKey.v1", )
    secure = True

    def __init__(self, authSvc, key, realms=None):
        self.agent = authSvc
        self.key = key
        self.realms = realms

    def __repr__(self):
        return "{0.__class__.__name__}({0.agent!r}, {0.key.id!r})".format(self)


    @inlineCallbacks
    def authorize(self, scheme, **params):
        identifier = self.getIdentifierInRealm(params["realm"])
        if identifier:
            log.debug("Using idenitifier {0} for realm {1[realm]}".format(
                    identifier, params), system=repr(self))
            cred = {"challenge": params["challenge"],
                    "realm": params["realm"],
                    "id": identifier, }

            log.debug("Signing challenge with {0.key.id}".format(self))
            try:
                cred["signature"] = yield self.signAuth(cred)
                log.debug("Signed challenge")

                auth = ", ".join(["{0}=\"{1}\"".format(*i) for i in cred.items()])
                authorization = "{0} {1}".format(scheme, auth)
                log.debug("Authorization: {0}".format(authorization))

            except:
                log.err()
                raise

        else:
            log.debug("{0.key.id} has no idenitifier in realm {1}".format(
                    self, params["realm"]), system=repr(self))
            authorization = None
            yield succeed(True)

        returnValue(authorization)


    def getIdentifierInRealm(self, realm):
        # Nb, lack of realm spec means .*  (No means yes)
        if not self.realms:
            return os.getlogin()
        for realmSpec in self.realms:
            if "realm" not in realmSpec or realmSpec["realm"].match(realm):
                return realmSpec.get("id") or os.getlogin()
        return None


    _authFmt = "{0[id]};{0[realm]};{0[challenge]}"

    @inlineCallbacks
    def signAuth(self, auth):
        data = self._authFmt.format(auth)
        signature = yield self.agent.signData(self.key.id, data)
        returnValue(signature.encode("base64").replace("\n", ""))

