"""
PubKey.v1 Client Authenticator module
"""

from twisted.conch.ssh.agent import SSHAgentClient  #, SSHAgentServer
from twisted.internet.defer import inlineCallbacks, returnValue

from pendrell.auth import IAuthenticator


class PubKeyAuthenticator(object):
    implements(IAuthenticator)

    schemes = ("PubKey.v1", )
    secure = True

    def __init__(self, identifier, agent, pubKey):
        """
        Arguments:
          identifier --  
          agent --  
          pubKey --
        """
        self.identifier = identifier
        self.agent = agent
        self.pubKey = pubKey


    @inlineCallbacks
    def authorize(self, scheme, **params):
        cred = {"challenge": params["challenge"],
                "realm": params["realm"],
                "id": self.identifier, }
        cred["signature"] = yield self.signAuth(cred)

        auth = ", ".join(["{0}=\"{1}\"".format(*i) for i in cred.items()])
        log.debug("Authenticating: {0}".format(auth))
        returnValue("{0} {1}".format(scheme, auth))


    _authFmt = "{0[id]};{0[realm]};{0[challenge]}"

    @inlineCallbacks
    def signAuth(self, auth):
        data = self._authFmt.format(auth)
        signature = yield self.agent.signData(self.pubKey, data)
        returnValue(signature.encode("base64").replace("\n", ""))



class AuthAgentClient(SSHAgentClient):

    def __init__(self, *args, **kw):
        SSHAgentClient.__init__(self, *args, **kw)
        self.keys = []


    @inlineCallbacks
    def requestIdentities(self):
        self.keys = k = yield SSHAgentClient.requestIdentities(self)
        returnValue(k)



