from __future__ import absolute_import
from shared.HLProtocol import *

def handle( server , user , args , ref ):
	if user.hasPriv( PRIV_USER_INFO ):
		str = ""
		if len( list(server.fileserver.transfers.values()) ) == 0:
			str += "\r > No file transfers in progress."
		else:
			str += "\r > File transfers:"
			str += "\r > TYPE  PCT  SPEED OWNER         NAME"
			for xfer in server.fileserver.transfers.values():
				type = ( "[DL]" , "[UL]" )[xfer.type]
				u = server.getUser( xfer.owner )
				speed = "%3dk/s" % ( xfer.getTotalBPS() / 1024 )
				owner = "<none>"
				if u != None:
					owner = u.nick
				str += "\r > %4s %3d%% %s %-13.13s %s" % ( type , xfer.overallPercent() , speed , owner , xfer.name )
		chat = HLPacket( HTLS_HDR_CHAT )
		chat.addString( DATA_STRING , str )
		if ref > 0:
			chat.addInt32( DATA_CHATID , ref )
		server.sendPacket( user.uid , chat )
