
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.usage import UsageError

from zope.interface import implements

from pub.client import cli


class Command(cli.Command):

    _longEntityFmt = "{0.id}\t{0.species}\t{0.primaryKeyId}"

    @inlineCallbacks
    def execute(self):
        if self.config["ids"]:
            ids = self.config["ids"]
        else:
            ids = yield self.pub.listEntities()

        if self.config["long"]:
            for id in ids:
                ent = yield self.pub.getEntity(id)
                print self._longEntityFmt.format(ent)
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

