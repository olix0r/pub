import sys

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.usage import UsageError

from zope.interface import implements

from jersey import log

from pub import crypto
from pub.client import cli
from pub.iface import EntityNotFound


class Command(cli.Command):

    _longEntityFmt = "{0.id}\t{0.species}\t{0.primaryKeyId}"

    def _getMaxLen(self, fields):
        m = 0
        for f in fields:
            m = max(m, len(f))
        return m


    @inlineCallbacks
    def execute(self):
        log.debug("Configured with {0}".format(self.config.parent.items()))
        if "entities" in self.config:
            entityIds = self.config["entities"]
        else:
            entityIds = yield self.pub.listEntities()
        
        p = self._getMaxLen(entityIds)
        for eid in entityIds:
            try:
                ent = yield self.pub.getEntity(eid)

                keyInfos = yield ent.listKeys()
                for (keyId, (keyType, comment)) in keyInfos.iteritems():
                    if self.config["fingerprint"]:
                        pubKey = yield ent.getKey(keyId)
                        keyData = pubKey.data.decode("base64")
                        key = crypto.Key.fromString(keyData)
                        keyId = key.fingerprint()
                    print "{eid:{p}} {type} {kid} {comment} ".format(
                            eid=eid, p=p, kid=keyId, type=keyType,
                            comment=comment)

            except EntityNotFound:
                print >>sys.stderr, "{eid:{p}} Not found".format(eid=eid, p=p)
                self.returnValue = 1



class Options(cli.Options):

    optFlags = (
            ("fingerprint", "f", "Show full fingerprints instead of key IDs"),
        )

    def opt_entity(self, entity):
        """Entity to list keys for.  May be specified multiple times.
        """
        self.setdefault("entities", []).append(entity)

    opt_e = lambda s,e: s.opt_entity(e)



class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "list-keys"
    shortcut = "k"
    description = "List all entities"


loader = Loader()

