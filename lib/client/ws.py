import json

from twisted.application.service import MultiService
from twisted.web import http

import pendrell
from pendrell.errors import WebError

f))rom pub import iface
from pub.ws import PubJSONEncoder


class PubAgent(pendrell.Agent):

    class requestClass(messages.Request):

        class responseClass(messages.BufferedResponse):

            _jsonType = "application/json"

            def done(self):
                if "Content-type" in self.headers:
                    ctype = self.headers["Content-type"][0]
                    if ctype == "application/json":
                        self.json = json.decodes(self.content)
                    else:
                        self.json = None
                else:
                    self.json = None



class PubService(MultiService):
    implements(iface.IPubService)

    def __init__(self, config):
        self.config = config
        self.baseUrl = self.config["server"]
        self.authConfig = config.readAuthConfig()


    #@inlineCallbacks
    def startService(self):
        pass


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

        key = self._buildKey(rsp.json["key"])
        returnValue(key)


    def registerKey(self, key, comment):
        raise NotImplemented()


    def _buildKey(self, params):
        try:
            key = Key.fromString(params["data"])
        except:
            raise ValueError("Invalid key data")
        comment = params["comment"]
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



