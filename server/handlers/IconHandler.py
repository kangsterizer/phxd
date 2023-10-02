from __future__ import absolute_import
from shared.HLProtocol import *
from shared.HLTypes import *
from struct import pack
from config import *

def installHandler( server ):
	if ENABLE_GIF_ICONS:
		server.registerPacketHandler( IconHandler() )

class IconHandler( HLPacketHandler ):
	def __init__( self ):
		HLPacketHandler.__init__( self )
		self.registerHandlerFunction( HTLC_HDR_ICON_LIST , self.handleIconList )
		self.registerHandlerFunction( HTLC_HDR_ICON_SET , self.handleIconSet )
		self.registerHandlerFunction( HTLC_HDR_ICON_GET , self.handleIconGet )
	
	def handleIconList( self , server , user , packet ):
		list = HLPacket( HTLS_HDR_TASK , packet.seq )
		for u in server.getOrderedUserlist():
			data = pack( "!2H" , u.uid , len( u.gif ) ) + u.gif
			list.addBinary( DATA_GIFLIST , data )
		server.sendPacket( user.uid , list )
	
	def handleIconSet( self , server , user , packet ):
		user.gif = packet.getBinary( DATA_GIFICON , "" )
		if len( user.gif ) > MAX_GIF_SIZE:
			user.gif = ""
			raise HLException("GIF icon too large.")
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
		change = HLPacket( HTLS_HDR_ICON_CHANGE )
		change.addNumber( DATA_UID , user.uid )
		server.broadcastPacket( change )
	
	def handleIconGet( self , server , user , packet ):
		uid = packet.getNumber( DATA_UID , 0 )
		info = server.getUser( uid )
		if info != None:
			icon = HLPacket( HTLS_HDR_TASK , packet.seq )
			icon.addNumber( DATA_UID , info.uid )
			icon.addBinary( DATA_GIFICON , info.gif )
			server.sendPacket( user.uid , icon )
		else:
			raise HLException("Invalid user.")
