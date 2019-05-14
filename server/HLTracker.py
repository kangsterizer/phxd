from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientFactory, ClientCreator
from config import *
from shared.HLProtocol import buildTrackerClientPacket
from shared.HLTypes import LOG_TYPE_TRACKER

class TrackerConnection(Protocol):
    """Client that deals with talking to a connected
    HL tracker daemon.
    """
    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        """
        A connection to a remote tracker was established.
        Send the name, description and user count of the
        currently running server instance.
        """
        userCount = self.factory.server.getUserCount()
        packet = buildTrackerClientPacket(SERVER_NAME, SERVER_DESCRIPTION, userCount)
        self.transport.write(packet)
        self.transport.loseConnection()

class HLTrackerClient(ClientFactory):
    """Factory producing Tracker Clients used for communicating
    with HL tracker daemons over a network.
    """
    def __init__(self, server, hostname, port):
        self.server = server
        self.hostname = hostname
        self.port = port

    def buildProtocol(self, addr):
        """Called when the factory has connected to an endpoint
        and is ready to transmit protocol specific data.
        """
        return TrackerConnection(self) 

    def update(self):
        """Updates the specified tracker on a successful connection."""
        reactor.connectTCP(self.hostname, self.port, self)

    def clientConnectionLost(self, connector, reason):
        self.server.logEvent(LOG_TYPE_TRACKER, "Tracker {}:{} lost connection:"
                             " {}".format(self.hostname, self.port,
                             reason.getErrorMessage().strip()))

    def clientConnectionFailed(self, connector, reason):
        self.server.logEvent(LOG_TYPE_TRACKER, "Tracker {}:{}: connect failed:"
                             " {}".format(self.hostname, self.port,
                             reason.getErrorMessage().strip()))

