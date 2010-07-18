
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.usage import UsageError

from zope.interface import implements

from pub.client import cli


class Command(cli.Command):

    _longEntityFmt = "{0.id}\t{0.species}\t{0.primaryKeyId}"

    def _getMaxLen(self, fields):
        m = 0
        for f in fields:
            m = max(m, len(f))
        return m


    @inlineCallbacks
    def execute(self):
        entityIds = yield self.pub.listEntities()
        p = self._getMaxLen(entityIds)
        
        for eid in entityIds:
            ent = yield self.pub.getEntity(eid)
            keyInfos = yield ent.listKeys()
            for keyInfo in keyInfos:
                print "{eid:{p}} {0} {2} ".format(*keyInfo, eid=eid, p=p)



class Options(cli.Options):

    #optFlags = [
    #        ["long", "l", "Print more information about entities."],
    #    ]

    def parseArgs(self, *ids):
        self["ids"] = ids

    def postOptions(self):
        if self["ids"]:
            self["long"] = True


class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "list-keys"
    shortcut = "k"
    description = "List all entities"


loader = Loader()

