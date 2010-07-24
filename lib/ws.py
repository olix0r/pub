"""
Pub Web Swervice
"""

import json

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python.components import registerAdapter

from twisted.web import http
from twisted.web.client import HTTPClientFactory
from twisted.web.resource import IResource, Resource
from twisted.web.server import NOT_DONE_YET
from twisted.web.util import DeferredResource

from jersey import log

from pub.iface import (IPubService, IEntity, IPublicKey,
        EntityNotFound, KeyNotFound, KeyAlreadyExists)



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
                    "comment": obj.comment,
                    "entityId": obj.entityId,
                    }
        elif isinstance(obj, Exception):
            return {"type": obj.__class__.__name__,
                    "args": obj.args,
                    }
        else:
            return super(PubJSONEncoder, self).default(obj)


def jsonize(obj, request=None):
    if request:
        r = json.dump(obj, request, cls=PubJSONEncoder)
        request.write("\n")
    else:
        r = json.dumps(obj, cls=PubJSONEncoder) + "\n"
    return r



class PubResource(Resource):

    jsonize = staticmethod(jsonize)

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


    @inlineCallbacks
    def _handleErrors(self, open, request):
        try:
           rsp = yield open(request)

        except Exception, err:
            log.err()
            if isinstance(err, (EntityNotFound, KeyNotFound, KeyAlreadyExists)):
                request.setResponseCode(http.BAD_REQUEST)
            else:
                request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.setHeader("Content-type", "application/json")
            self.jsonize({"error": err}, request)
            request.finish()

        else:
            returnValue(rsp)


class PubServiceResource(PubResource):

    def __init__(self, pubSvc):
        PubResource.__init__(self)
        self.pubSvc = pubSvc

        self.putChild("", self)
        self.putChild("entities", EntitiesResource(pubSvc))


    def render_GET(self, request):
        uri = request.URLPath().here()
        request.setHeader("Content-type", "application/json")
        return self.jsonize({"links": [
                {"rel":"self", "href":"{0}".format(uri), },
                {"rel":"Entities", "href":"{0}entities".format(uri), },
                ]})


registerAdapter(PubServiceResource, IPubService, IResource)



class EntitiesResource(PubResource):

    suffixTypes = {"json": "application/json", }

    def __init__(self, pubSvc):
        PubResource.__init__(self)
        self.pubSvc = pubSvc

        self.putChild("", self)


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
        self._handleErrors(self._listEntities, request)
        return NOT_DONE_YET

    @inlineCallbacks
    def _listEntities(self, request):
        ents = yield self.pubSvc.listEntities()
        request.setHeader("Content-type", "application/json")
        self.jsonize({"entities": ents}, request)
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
        request.setHeader("Content-type", "application/json")
        return self.jsonize({
            "entity": self.entity,
            "links": [
                {"rel":"self", "href":"{0}".format(uri), },
                {"rel":"Public Keys", "href":"{0}keys".format(uri), },
                ]})



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
        self._handleErrors(self._listKeys, request)
        return NOT_DONE_YET

    @inlineCallbacks
    def _listKeys(self, request):
        keyInfos = yield self.entity.listKeys()
        request.setHeader("Content-type", "application/json")
        self.jsonize({"keys": keyInfos}, request)
        request.finish()


    def render_POST(self, request):
        log.debug("Registering key from POST: {0}".format(request))
        self._handleErrors(self._registerKey, request)
        return NOT_DONE_YET

    @inlineCallbacks
    def _registerKey(self, request):
        posted = json.load(request.content)
        keyInfo = posted["key"]

        if "entityId" in keyInfo and keyInfo["entityId"] != self.entity.id:
            raise RuntimeError("Bad entity ID")

        keyData = keyInfo["data"].decode("base64")
        log.debug("Registering key: {0}".format(keyInfo["id"]))
        key = yield self.entity.registerKey(keyData, keyInfo["comment"])
        log.debug("Registered key: {0}".format(key))

        request.setHeader("Content-type", "application/json")
        self.jsonize({"key": key}, request)
        request.finish()



class PubKeyResource(PubResource):

    def __init__(self, key, suffix=None):
        PubResource.__init__(self, suffix)
        self.pubKey = key

    def render_GET(self, request):
        request.setHeader("Content-type", "application/json")
        return self.jsonize({"key": self.pubKey})


