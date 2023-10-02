from __future__ import absolute_import
from shared.HLProtocol import *
def handle( server , user , arg , ref ):
	if len( arg ) > 0:
		if user.status != int(arg):
			user.status = int(arg)
			server.dispatchPacket( user.uid, HLPacket(HTLC_HDR_USER_CHANGE) )
