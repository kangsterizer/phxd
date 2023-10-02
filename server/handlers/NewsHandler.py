from __future__ import absolute_import
from shared.HLProtocol import *
from shared.HLTypes import *
from config import *

def installHandler( server ):
	server.registerPacketHandler( NewsHandler() )

def formatPost( post ):
	str = "From %s [%s] (%s):\r\r%s\r_________________________________________________________\r" % \
		( post.nick , post.login , post.date , post.post )
	return str

class NewsHandler( HLPacketHandler ):
	def __init__( self ):
		HLPacketHandler.__init__( self )
		self.registerHandlerFunction( HTLC_HDR_NEWS_GET , self.handleNewsGet )
		self.registerHandlerFunction( HTLC_HDR_NEWS_POST , self.handleNewsPost )
	
	def handleNewsGet( self , server , user , packet ):
		limit = packet.getNumber( DATA_NEWSLIMIT , 0 )
		if user.hasPriv( PRIV_READ_NEWS ):
			str = ""
			posts = server.database.loadNewsPosts( limit )
			for post in posts:
				str += formatPost( post )
			str = str[0:65535]
			news = HLPacket( HTLS_HDR_TASK , packet.seq )
			news.addString( DATA_STRING , str )
			server.sendPacket( user.uid , news )
		else:
			raise HLException("You are not allowed to read the news.")
	
	def handleNewsPost( self , server , user , packet ):
		str = packet.getString( DATA_STRING , "" )
		if user.hasPriv( PRIV_POST_NEWS ):
			if len( str ) > 0:
				post = HLNewsPost( user.nick , user.account.login , str )
				server.database.saveNewsPost( post )
				notify = HLPacket( HTLS_HDR_NEWS_POST )
				notify.addString( DATA_STRING , formatPost( post ) )
				server.broadcastPacket( notify , PRIV_READ_NEWS )
				server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
		else:
			raise HLException("You are not allowed to post news.")
