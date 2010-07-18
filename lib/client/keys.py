
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.plugin import IPlugin
from twisted.python.usage import UsageError

from zope.interface import implements

from jersey import log
from pub.client import cli


class Command(cli.Command):

    @inlineCallbacks
    def execute(self):
        ids = yield self.pub.listEntities()
        for id in ids:
            ent = yield self.pub.getEntity(id)
            log.msg("Got entity: {0.id}".format(ent))
            keys = yield ent.listKeys()
            log.msg("Got {0} keys".format(len(keys)))
            for key in keys:
                print "{0}\t{1}".format(id, key[0])


class Options(cli.Options):
    pass


class Loader(cli.CommandFactory):
    implements(IPlugin)

    command = Command
    options = Options

    name = "keys"
    shortcut = "k"
    description = "List all keys"


loader = Loader()

