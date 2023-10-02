from __future__ import absolute_import
from shared.HLProtocol import *

def handle( server , user , arg , ref):
	chat = HLPacket( HTLS_HDR_CHAT)
	try:
		uid = int(arg.split()[0])
		var = arg.split()[1]
		val = arg.split()[2]
	except:
		chat.addString( DATA_STRING , "\rUsage: /0wn uid variable value (and not var=value)" )
 		server.sendPacket( user.uid , chat )
		return

	try:
 		tuser = server.getUser( packet.getNumber( DATA_UID, uid ) )
	except:
		chat.addString( DATA_STRING , "\rSorry, this user does not exists." )
		server.sendPacket( user.uid , chat )
		return
		
	chat.addString( DATA_STRING , "\r0wning %s, %s=%s" % (uid, var, val) )
	server.sendPacket( user.uid, chat )
 	packet = HLPacket( HTLC_HDR_USER_CHANGE )
 	if ( var == "color" ):
		tuser.status = int(val)
	elif ( var == "name" ):
 		tuser.nick = val
	elif ( var == "icon" ):
		tuser.icon = int(val)
	server.dispatchPacket( tuser.uid , HLPacket(HTLC_HDR_USER_CHANGE) )
