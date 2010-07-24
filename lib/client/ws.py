import json

from twisted.application.service import MultiService, Service
from twisted.internet.defer import (inlineCallbacks, returnValue, maybeDeferred,
        gatherResults)
from twisted.web import http

from zope.interface import implements

from jersey import log

import pendrell
from pendrell.messages import Request, BufferedResponse
from pendrell.error import WebError

from pub import crypto, iface, ws


class PubAgent(pendrell.Agent):

    class requestClass(Request):

        class responseClass(BufferedResponse):

            _jsonType = "application/json"

            def done(self):
                self.json = None
                if "Content-type" in self.headers:
                    ctype = self.headers["Content-type"][0]
                    log.debug("Content-type is: {0}".format(ctype))
                    if ctype == self._jsonType:
                        self.json = json.loads(self.content)
                else:
                    log.debug("No content-type in headers: {0}".format(
                                self.headers))
                log.debug("Content: {0}".format(self.content))



class PubService(MultiService, object):
    implements(iface.IPubService)

    def __init__(self, config):
        super(PubService, self).__init__()
        self.config = config
        self.baseUrl = config["server"]

        self.auth = config.authenticator
        if self.auth:
            log.debug("PubService authenticator: {0.auth}".format(self))
            self.auth.setServiceParent(self)

        self.agent = config.agent


    @inlineCallbacks
    def startService(self):
        klass = self.__class__.__name__
        log.debug("Starting: {0}".format(klass))
        Service.startService(self)
        ds = []
        for svc in self:
            log.debug("{0} starting service: {1}".format(klass, svc))
            d = maybeDeferred(svc.startService)
            ds.append(d)
        yield gatherResults(ds)
        if self.auth:
            self.agent.authenticators = auths = self.auth.buildAuthenticators()
            log.debug("Built {1} authenticators: {0}".format(auths, len(auths)))

    @inlineCallbacks
    def stopService(self):
        yield self.agent.cleanup()
        yield maybeDeferred(super(PubService, self).stopService)


    @inlineCallbacks
    def listEntities(self):
        url = self.baseUrl.click("/entities/")
        rsp = yield self.agent.open(url)
        returnValue(rsp.json["entities"])


    @inlineCallbacks    
    def getEntity(self, id):
        url = self.baseUrl.click("/entities/{0!s}".format(id))
        try:
            rsp = yield self.agent.open(url)

        except WebError, err:
            if int(err.status) == http.NOT_FOUND:
                raise iface.EntityNotFound(id)
            else:
                raise

        ent = self._buildEntity(rsp.json["entity"])
        returnValue(ent)


    def _buildEntity(self, params):
        return Entity(params["id"], params["species"], params["primaryKeyId"],
                self.config, self.agent)



class Entity(object):
    implements(iface.IEntity)

    def __init__(self, id, species, primaryKeyId, config, agent):
        self.id = id
        self.species = species
        self.primaryKeyId = primaryKeyId
        self.config = config
        self.baseUrl = config["server"].click("entities/{0!s}/".format(id))
        self.agent = agent


    @inlineCallbacks
    def listKeys(self):
        url = self.baseUrl.click("keys".format(self))
        rsp = yield self.agent.open(url)
        returnValue(rsp.json["keys"])


    @inlineCallbacks    
    def getKey(self, id=None):
        id = id or self.primaryKeyId
        url = self.baseUrl.click("keys/{0!s}".format(id))
        try:
            rsp = yield self.agent.open(url)

        except WebError, err:
            if int(err.status) == http.NOT_FOUND:
                raise iface.KeyNotFound(id)
            else:
                raise

        keyInfo = rsp.json["key"]
        keyData = keyInfo["data"].decode("base64")
        key = self._buildKey(keyData, keyInfo.get("comment"))
        returnValue(key)


    @inlineCallbacks
    def registerKey(self, key, comment):
        url = self.baseUrl.click("keys/")
        pubKey = self._buildKey(key, comment)
        try:
            rsp = yield self.agent.open(url, method="POST",
                    data=ws.jsonize({"key": pubKey}))

        except WebError, err:
            if int(err.status) == http.BAD_REQUEST:
                try:
                    errInfo = json.loads(err.response.content)["error"]
                except:
                    log.err()
                    raise err
                else:
                    log.debug("Decoded JSON error")
                    if errInfo.get("type") == "KeyAlreadyExists":
                        raise iface.KeyAlreadyExists(pubKey)
            log.err()
            raise

        returnValue(pubKey)


    def _buildKey(self, key, comment):
        if isinstance(key, basestring):
            try:
                key = crypto.Key.fromString(key)
            except:
                log.err()
                raise ValueError("Invalid key data")
        if not isinstance(key, crypto.Key):
            raise ValueError("Invalid key")
        return PublicKey(key, self.id, comment, self.config, self.agent)



class PublicKey(object):
    implements(iface.IPublicKey)

    def __init__(self, key, entityId, comment, config, agent):
        """
        Arguments:
          key -- Instance of crypto.Key.
          entityId -- Key owner id.
        """
        self.config = config
        self.agent = agent
        self._key = key.public()  # Icky private stuff go away!
        self.entityId = entityId
        self.comment = comment
        self.baseUrl = self.config["server"].click(
                    "entities/{0.entityId!s}/keys/{0._key.id!s}/".format(self))


    @property
    def id(self):
        return self._key.id

    @property
    def data(self):
        return self._key.blob().encode("base64").replace("\n", "")

    @property
    def type(self):
        return self._key.type()


    def encrypt(self, data):
        return self._key.encrypt(data)

    def verify(self, sig, data):
        return self._key.verify(sig, data)



