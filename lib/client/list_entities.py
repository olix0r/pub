
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.usage import UsageError

from zope.interface import implements

from pub.client import cli
from pub.iface import EntityNotFound


class Command(cli.Command):

    def _getMaxLen(self, fields):
        m = 0
        for f in fields:
            m = max(m, len(f))
        return m


    _longEntityFmt = "{0.id:{p}}  {0.species}  {0.primaryKeyId}"

    @inlineCallbacks
    def execute(self):
        if self.config["ids"]:
            ids = self.config["ids"]
        else:
            ids = yield self.pub.listEntities()
        p = self._getMaxLen(ids)

        if self.config["long"]:
            for id in ids:
                try:
                    ent = yield self.pub.getEntity(id)
                except EntityNotFound:
                    print "{0:{p}}  Not found".format(id, p=p)
                else:
                    print self._longEntityFmt.format(ent, p=p)
        else:
            print "\n".join(ids)



class Options(cli.Options):

    optFlags = [
            ["long", "l", "Print more information about entities."],
        ]

    def parseArgs(self, *ids):
        self["ids"] = ids

    def postOptions(self):
        if self["ids"]:
            self["long"] = True


class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "list-entities"
    shortcut = "e"
    description = "List all entities"


loader = Loader()

