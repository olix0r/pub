
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.filepath import FilePath
from twisted.python.usage import UsageError

from zope.interface import implements

from pub.client import cli
from pub.crypto import Key



class Options(cli.Options):

    def getSynopsis(self):
        return "{0} {1} id".format(
                self.parent.getSynopsis(),
                self.parent.subCommand)

    def parseArgs(self, id):
        self["id"] = id



class Command(cli.Command):

    _entFmt = "\n".join([
            "Identifier:  {0.id}",
            "Species:     {0.species}",
            "Primary key: {0.primaryKeyId}",
            ])


    @inlineCallbacks
    def execute(self):
        ent = yield self.pub.getEntity(self.config["id"])
        yield self.pub.unregisterEntity(self.config["id"])
        print self._entFmt.format(ent)


class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "unregister-entity"
    shortcut = "u"
    description = "Unregister an entity"


loader = Loader()

