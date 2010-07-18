import sys

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.usage import UsageError

from zope.interface import implements

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
        if "entities" in self.config:
            entityIds = self.config["entities"]
        else:
            entityIds = yield self.pub.listEntities()
        
        p = self._getMaxLen(entityIds)
        for eid in entityIds:
            try:
                ent = yield self.pub.getEntity(eid)

            except EntityNotFound:
                print >>sys.stderr, "{eid:{p}}  Not found".format(eid=eid, p=p)
                self.returnValue = 1

            else:
                keyInfos = yield ent.listKeys()
                for keyInfo in keyInfos:
                    print "{eid:{p}}  {0}  {2} ".format(*keyInfo, eid=eid, p=p)



class Options(cli.Options):

    def opt_entity(self, entity):
        """Entity to list keys for.  May be specified multiple times.
        """
        self.setdefault("entities", []).append(entity)


class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "list-keys"
    shortcut = "k"
    description = "List all entities"


loader = Loader()

