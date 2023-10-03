from shared.HLProtocol import *

def handle( server , user , args , ref ):
	user.away = not user.away
	oldStatus = user.status
	if user.away:
		user.status |= STATUS_AWAY
	else:
		user.status &= ~STATUS_AWAY
	if user.status != oldStatus:
		# Only send the change if our status actually changed.
		server.dispatchPacket( user.uid , HLPacket( HTLC_HDR_USER_CHANGE ) )
