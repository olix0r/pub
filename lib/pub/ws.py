"""

"""

import json

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python.components import registerAdapter

from twisted.web.client import HTTPClientFactory
from twisted.web.resource import IResource, Resource
from twisted.web.server import NOT_DONE_YET
from twisted.web.util import DeferredResource

from jersey import log
from jersey.cred.pub.iface import (IPubService, IEntity, IPublicKey,
        EntityNotFound, KeyNotFound)



class PubResource(Resource):

    def __init__(self, suffix=None):
        Resource.__init__(self)
        self.suffix = suffix


    @staticmethod
    def splitResourceSuffix(name):
        if "." in name:
            name, suffix = name.rsplit(".", 1)
        else:
            suffix = None
        return name, suffix


    def suffixIsSupported(self, suffix):
        return bool(suffix in getattr(self, "suffixTypes", {}))


    def determineResponseContentType(self, request):
        #if self.suffix is None:
        #    accept = request.requestHeaders.getRawHeaders("accept", [None])[0]
        #    if accept:
        #        contentType = accept
        return getattr(self, "suffixTypes", {}
                ).get(self.suffix, self.defaultType)



class PubServiceResource(PubResource):

    def __init__(self, pubSvc):
        PubResource.__init__(self)
        self.pubSvc = pubSvc

        self.putChild("", self)
        self.putChild("entities", EntitiesResource(pubSvc))


    def render_GET(self, request):
        uri = request.URLPath().here()
        return json.dumps({"links": [
                {"rel":"self", "href":"{0}".format(uri), },
                {"rel":"Entities", "href":"{0}entities".format(uri), },
                ]}, cls=PubJSONEncoder) + "\n"


registerAdapter(PubServiceResource, IPubService, IResource)



class EntitiesResource(PubResource):

    suffixTypes = {"json": "application/json", }

    def __init__(self, pubSvc):
        PubResource.__init__(self)
        self.pubSvc = pubSvc


    def getChild(self, name, request):
        return DeferredResource(self._getDeferredChild(name, request))


    @inlineCallbacks
    def _getDeferredChild(self, name, request):
        try:
            entity = yield self.pubSvc.getEntity(name)

        except KeyError:
            baseName, sfx = self.splitResourceSuffix(name)
            try:
                entity = yield self.pubSvc.getEntity(baseName)
            except KeyError:
                resource = Resource.getChild(self, name, request)
            else:
                resource = self.buildEntityResource(baseName, entity, sfx)
                if not resource.suffixIsSupported(sfx):
                    resource = Resource.getChild(self, name, request)
        else:
            resource = self.buildEntityResource(name, entity)

        returnValue(resource)


    def buildEntityResource(self, name, entity, suffix=None):
        return EntityResource(entity, suffix)


    def render_GET(self, request):
        self._listEntities(request)
        return NOT_DONE_YET

    @inlineCallbacks
    def _listEntities(self, request):
        ents = yield self.pubSvc.listEntities()
        json.dump({"entities": ents}, request, cls=PubJSONEncoder)
        request.write("\n")
        request.finish()



class EntityResource(PubResource):

    suffixTypes = {"json": "application/json", }

    def __init__(self, entity, suffix=None):
        PubResource.__init__(self)
        self.entity = entity
        self.suffix = suffix

        self.putChild("", self)
        self.putChild("keys", EntityKeysResource(self.entity))


    def render_GET(self, request):
        uri = request.URLPath().here()
        return json.dumps({
            "entity": self.entity,
            "links": [
                {"rel":"self", "href":"{0}".format(uri), },
                {"rel":"Public Keys", "href":"{0}keys".format(uri), },
                ]}, cls=PubJSONEncoder) + "\n"



class EntityKeysResource(PubResource):

    def __init__(self, entity, suffix=None):
        PubResource.__init__(self, suffix)
        self.entity = entity

        self.putChild("", self)


    def getChild(self, name, request):
        return DeferredResource(self._getDeferredChild(name, request))


    @inlineCallbacks
    def _getDeferredChild(self, name, request):
        try:
            key = yield self.entity.getKey(name)

        except KeyError:
            origName = name
            name, sfx = self.splitResourceSuffix(name)
            try:
                entity = yield self.entity.getKey(name)
            except KeyError:
                resource = super(EntityKeysResource, self
                        ).getChild(self, name, request)
            else:
                resource = self.buildKeyResource(baseName, key, sfx)
                if not resource.suffixIsSupported(sfx):
                    resource = super(EntityKeysResource, self
                            ).getChild(self, origName, request)
        else:
            resource = self.buildKeyResource(name, key)

        returnValue(resource)

    def buildKeyResource(self, name, key, sfx=None):
        return PubKeyResource(key, sfx)


    def render_GET(self, request):
        self._listKeys(request)
        return NOT_DONE_YET

    @inlineCallbacks
    def _listKeys(self, request):
        keyList = yield self.entity.listKeys()
        keyInfos = {}
        for (id, type, comment) in keyList:
            keyInfos[id] = type, comment
        json.dump({"keys": keyInfos}, request, cls=PubJSONEncoder)
        request.write("\n")
        request.finish()



class PubKeyResource(PubResource):

    def __init__(self, key, suffix=None):
        PubResource.__init__(self, suffix)
        self.pubKey = key

    def render_GET(self, request):
        return json.dumps({"key": self.pubKey}, cls=PubJSONEncoder) + "\n"


class PubJSONEncoder(json.JSONEncoder):

    def default(self, obj):
        log.debug("Finding JSON representation for {0!r}".format(obj))
        if IEntity.providedBy(obj):
            return {"id": obj.id,
                    "species": obj.species,
                    "primaryKeyId": obj.primaryKeyId,
                    }

        elif IPublicKey.providedBy(obj):
            return {"id": obj.id,
                    "type": obj.type,
                    "data": obj.data,
                    "entityId": obj.entityId,
                    }

        else:
            return super(PubJSONEncoder, self).default(obj)


