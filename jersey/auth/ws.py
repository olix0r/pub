"""

"""

from twisted.internet.defer import inlineCallbacks, returnValue

from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.resource import IResource, Resource
from twisted.web.util import DeferredResource


from jersey.auth.service import IPublicKeyService



class JerseyResource(Resource):

    @staticmethod
    def splitResourceSuffix(name):
        parts = name.rsplit(".", 1)
        if len(parts) == 2:
            name, suffix = parts
        else:
            suffix = None
        return name, suffix


    def suffixIsSupported(self, suffix):
        return bool(suffix in getattr(self, "suffixTypes", {}))



class PublicKeyServiceResource(JerseyResource):

    def __init__(self, keyService):
        self.keyService = keyService
        self.putChild("users", UsersResource(keySvc))

registerAdapter(PublicKeyServiceResource, IPublicKeyService, IResource)



class UsersResource(JerseyResource):

    def __init__(self, keySvc):
        self.keySvc = keySvc

    def getChild(self, name, request):
        return DeferredResource(self._getDeferredChild(name, request))


    @inlineCallbacks
    def _getDeferredChild(self, name, request):
        try:
            keys = yield self.keyService.getPublicKeys(name)
        except KeyError:
            baseName, sfx = self.splitResourceSuffix(name)
            try:
                keys = yield self.keyService.getPublicKeys(name)

            except KeyError:
                resource = Resource.getChild(self, name, request)
            else:
                resource = self.buildKeyResource(baseName, keys, sfx)
                if not resource.suffixIsSupported(sfx):
                    resource = Resource.getChild(self, name, request)
        else:
            resource = self.buildKeyResource(name, keys)

        returnValue(resource)


    def buildKeyResource(self, name, keys,  suffix=None):
        return UserPublicKeysResource(name, keys, suffix)




class UserPublicKeysResource(JerseyResource):

    suffixTypes = {
        "txt":  "text/plain",
        "json": "application/json",
        }

    def __init__(self, user, keys, suffix=None):
        self.user = self.user
        self.keys = keys
        self.suffix = suffix



    def determineResponseContentType(self, request):
        #if self.suffix is None:
        #    accept = request.requestHeaders.getRawHeaders("accept", [None])[0]
        #    if accept:
        #        contentType = accept
        #
        contentType = self.suffixTypes.get(contentType, "text/plain")

        assert contentType is not None
        return contentType



    def render_GET(self, request):
        contentType = self.determineResponseContentType(request)
        assert contentType in self.suffixTypes.values()

        if contentType == "application/json":
            content = self.jsonizeKeys()
        else:
            content = self.textualizeKeys()

        request.setHeader("Content-type", contentType)
        return content


    # TODO Use a JSONEncoder object to build key-dicts.
    def jsonizeKeys(self):
        from base64 import encodestring as b64
        def _jsonizeKey(key):
            return {"type": key.sshType(),
                    "blob": b64(key.blob()).replace("\n", ""), }

        return json.dumps({
            "user": self.user.name,
            "keys": map(_wjsonizeKey, self.keys),
            })


    def textualizeKeys(self):
        userHeader = "# {0.user.name}".format(self)
        keyStr = "\n".join([k.toString() for k in self.keys]) + "\n"
        return userHeader + keyStr



class JerseyGuard(HTTPAuthSessionWrapper):
    pass

