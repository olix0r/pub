"""

"""

import json

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python.components import registerAdapter

from twisted.web.client import HTTPClientFactory
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.resource import IResource, Resource
from twisted.web.util import DeferredResource

from jersey import log
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

    def __init__(self, keySvc):
        JerseyResource.__init__(self)
        self.keySvc = keySvc

        self.putChild("", self)
        self.putChild("users", UsersResource(keySvc))


    def render(self, request):
        uri = request.URLPath().here()
        return json.dumps({"links": [
                {"rel":"self", "href":"{0}".format(uri), },
                {"rel":"User keys", "href":"{0}users".format(uri), },
                ]}) + "\n"


registerAdapter(PublicKeyServiceResource, IPublicKeyService, IResource)



class UsersResource(JerseyResource):

    def __init__(self, keySvc):
        JerseyResource.__init__(self)
        self.keySvc = keySvc

    def getChild(self, name, request):
        return DeferredResource(self._getDeferredChild(name, request))


    @inlineCallbacks
    def _getDeferredChild(self, name, request):
        try:
            keys = yield self.keySvc.getPublicKeys(name)

        except KeyError:
            baseName, sfx = self.splitResourceSuffix(name)
            try:
                keys = yield self.keySvc.getPublicKeys(baseName)

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


    def __init__(self, user, keys, suffix=None):
        JerseyResource.__init__(self)
        self.user = user
        self.keys = keys
        self.suffix = suffix


    def determineResponseContentType(self, request):
        #if self.suffix is None:
        #    accept = request.requestHeaders.getRawHeaders("accept", [None])[0]
        #    if accept:
        #        contentType = accept
        #
        return self.suffixTypes.get(self.suffix, "text/plain")


    def render_GET(self, request):
        contentType = self.determineResponseContentType(request)
        assert contentType in self.suffixTypes.values()
        if contentType == "application/json":
            content = self.jsonizeKeys()
        else:
            content = self.textualizeKeys()
        request.setHeader("Content-type", contentType)
        return content


    suffixTypes = {
        "txt":  "text/plain",
        "json": "application/json",
        }

    # TODO Use a JSONEncoder object to build key-dicts.
    def jsonizeKeys(self):
        def jsonizeKey(key):
            blob = key.blob().encode("base64").replace("\n", "")
            return {"type":key.sshType(), "blob":blob, }
        return json.dumps({
            "user": self.user,
            "keys": map(jsonizeKey, self.keys),
            })+"\n"


    def textualizeKeys(self):
        def textualizeKey(k):
            return "{0} {1}".format(k.toString("OPENSSH"), self.user)
        keys = map(textualizeKey, self.keys)
        return "\n".join(keys) + "\n"

    formatters = {
        "text/plain": textualizeKeys,
        "application/json": jsonizeKeys,
        }



class JerseyGuard(HTTPAuthSessionWrapper):

    def _login(self, creds):
        log.msg("Logging in: {0!r}".format(creds))
        return HTTPAuthSessionWrapper._login(self, creds)


    def _selectParseHeader(self, header):
        log.debug("Finding an authenticator for {0}".format(header))

        scheme, elements = header.split(' ', 1)
        for fact in self._credentialFactories:
            if fact.scheme.lower() == scheme.lower():
                log.debug("Found an authenticator: {0}".format(fact))
                return (fact, elements)

        log.warn("No matching authenticator found for {0}".format(scheme))
        return (None, None)


