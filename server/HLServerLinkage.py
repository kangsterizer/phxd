from __future__ import absolute_import
from __future__ import print_function
from twisted.internet import reactor
from twisted.internet.protocol import Protocol , Factory , ClientCreator
from shared.HLProtocol import *
from shared.HLTypes import *
from struct import *
from config import *

class LinkConnection( Protocol ):
	def __init__( self, factory ):
		self.factory = factory
		self.buffer = ""
		# maps local UIDs to remote UIDs for this link
		self.localToRemote = {}
		# maps remote UIDs to local UIDs for this link
		self.remoteToLocal = {}
	
	def connectionMade( self ):
		packet = HLPacket( HTLS_HDR_LINK_LOGIN )
		users = self.factory.server.getOrderedUserlist()
		for user in users:
			packet.addBinary( DATA_USER, user.flatten() )
		self.transport.write( packet.flatten() )
		self.factory.linkEstablished( self )
	
	def connectionLost( self, reason ):
		print("link connection lost")
	
	def dataReceived( self, data ):
		self.buffer += data
		self.parseBuffer()
	
	def parseBuffer( self ):
		done = False
		while not done:
			packet = HLPacket()
			size = packet.parse( self.buffer )
			if size > 0:
				self.buffer = self.buffer[size:]
				self.handleLinkPacket( packet )
			else:
				done = True
	
	def fixPacket( self, packet ):
		for obj in packet.objs:
			if obj.type == DATA_UID:
				remoteUID = unpack( "!H" , obj.data )[0]
				if remoteUID in self.remoteToLocal:
					localUID = self.remoteToLocal[remoteUID]
					obj.data = pack( "!H" , localUID )
				else:
					print("ERROR: unable to map remote UID [%d]" % remoteUID)
	
	def handleLinkPacket( self, packet ):
		if packet.type == HTLS_HDR_LINK_LOGIN:
			# the initial link login packet containing the remote userlist
			userObjs = packet.getObjects( DATA_USER )
			for obj in userObjs:
				user = HLUser()
				if user.parse(obj.data) > 0:
					localUID = self.factory.server.addRemoteUser( user, True )
					self.localToRemote[localUID] = user.uid
					self.remoteToLocal[user.uid] = localUID
		elif packet.type == HTLS_HDR_LINK_JOIN:
			# a user joined on the remote server
			user = HLUser()
			if user.parse( packet.getBinary(DATA_USER) ) > 0:
				localUID = self.factory.server.addRemoteUser( user, False )
				self.localToRemote[localUID] = user.uid
				self.remoteToLocal[user.uid] = localUID
		elif packet.type == HTLS_HDR_LINK_LEAVE:
			# a user left on the remote server
			user = HLUser()
			if user.parse( packet.getBinary(DATA_USER) ) > 0:
				if user.uid in self.remoteToLocal:
					localUID = self.remoteToLocal[user.uid]
					self.factory.server.removeRemoteUser( localUID )
		elif packet.type == HTLS_HDR_LINK_PACKET:
			# a packet is to be forwarded to a local user from a remote user
			localPacket = HLPacket()
			if localPacket.parse(packet.getBinary(DATA_PACKET)) > 0:
				localUID = packet.getNumber( DATA_UID )
				self.fixPacket( localPacket )
				self.factory.server.sendPacket( localUID, localPacket )
		else:
			print("ERROR: unknown link packet type")
	
	def forwardPacketData( self, data, uid ):
		if uid in self.localToRemote:
			remoteUID = self.localToRemote[uid]
			fwdPacket = HLPacket( HTLS_HDR_LINK_PACKET )
			fwdPacket.addNumber( DATA_UID, remoteUID )
			fwdPacket.addBinary( DATA_PACKET, data )
			self.transport.write( fwdPacket.flatten() )
		else:
			print("ERROR: unable to forward packet to local UID %d" % uid)

class HLServerLinker( Factory ):
	
	def __init__( self, server ):
		self.server = server
		self.links = []
		reactor.listenTCP( LINK_PORT, self )
	
	def buildProtocol( self, addr ):
		print("got link connection from %s" % addr.host)
		return LinkConnection( self )
	
	def linkEstablished( self, link ):
		print("added link")
		self.links.append( link )
	
	def link( self, addr, port ):
		print("linking to %s:%d" % (addr,port))
		c = ClientCreator( reactor, LinkConnection, self )
		c.connectTCP( addr, port )
	
	def forwardUserConnect( self, user ):
		packet = HLPacket( HTLS_HDR_LINK_JOIN )
		packet.addBinary( DATA_USER, user.flatten() )
		for link in self.links:
			link.transport.write( packet.flatten() )
	
	def forwardUserDisconnect( self, user ):
		packet = HLPacket( HTLS_HDR_LINK_LEAVE )
		packet.addBinary( DATA_USER, user.flatten() )
		for link in self.links:
			link.transport.write( packet.flatten() )
	
	def forwardPacket( self, packet, uid ):
		""" Forwards the given packet to each link, mapping the specified local
		UID to the correct remote UID on a per-link basis """
		packetData = packet.flatten()
		for link in self.links:
			link.forwardPacketData( packetData, uid )
