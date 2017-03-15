from shared.HLProtocol import *

def handle( server , user , arg , ref ):
	if len( arg ) > 0 and user.hasPriv( PRIV_BROADCAST ):
		broadcast = HLPacket( HTLS_HDR_BROADCAST )
		broadcast.addString( DATA_STRING , arg )
		server.broadcastPacket( broadcast )
