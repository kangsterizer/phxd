from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from config import *
from shared.HLProtocol import buildTrackerClientPacket
from shared.HLTypes import LOG_TYPE_TRACKER

class HLTrackerClient(DatagramProtocol):
    """Client that deals with sending UDP datagram
    to a HL tracker daemon
    """
    def __init__(self, server, hostname, port=5498):
        self.server = server
        self.hostname = hostname
        self.port = port

    def resolvedIP(self, ip):
        """
        Callback invoked when we have successfully resolved
        a hostname to an IP address that can be used to send
        UDP datagrams to that endpoint.
        """
        self.update(ip)

    def resolutionFailed(self, failure):
        """
        Errback invoked when we could not resolve the hostname
        of the specified HLTracker daemon.
        """
        errorMsg = failure.getErrorMessage()
        self.server.logEvent(LOG_TYPE_TRACKER, "Failed to update tracker {}:"
                             " {}".format(self.hostname, errorMsg))

    def startProtocol(self):
        """
        Called when the transport is connected. Resolve the
        hostname matching the tracker daemon if necessary and
        proceed to update the tracker daemon by sending a
        UDP packet.
        """
        resolver = reactor.resolve(self.hostname)
        resolver.addCallbacks(self.resolvedIP, self.resolutionFailed)

    def update(self, hostIP):
        """
        Sends a single UDP packet to the specified hostname and port,
        encoding the currently running phxd HL server instance user 
        count, server name, description and TCP port to reach it on.
        """
        self.transport.connect(hostIP, self.port)
        userCount = self.server.getUserCount()
        packet = buildTrackerClientPacket(SERVER_NAME, SERVER_DESCRIPTION,
                                          SERVER_PORT, userCount)
        self.transport.write(packet)
        self.server.logEvent(LOG_TYPE_TRACKER, "Updated tracker {}:{} with {} "
                             "users.".format(self.hostname, self.port, userCount))
        # We're done, close this connection.
        self.transport.loseConnection()

    def connectionRefused(self):
        """
        A datagram sent to a remote host port was refused.
        Log the event and move on. NOTE: Because of the nature
        of UDP this is unlikely to be called. This is called as
        a result of an ICMP response from a previous UDP packet.
        """
        self.server.logEvent(LOG_TYPE_TRACKER, "Connection refused from "
                             "{}:{}".format(self.hostname, self.port))
