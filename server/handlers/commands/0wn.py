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

    # NOTE: previously called ``packet.getNumber(...)`` here, but ``packet``
    # was undefined at this point (it's created several lines below). The
    # caller already gives us ``uid`` directly — use it.
    tuser = server.getUser( uid )
    if tuser is None:
        chat.addString( DATA_STRING , "\rSorry, this user does not exists." )
        server.sendPacket( user.uid , chat )
        return

    chat.addString( DATA_STRING , "\r0wning %s, %s=%s" % (uid, var, val) )
    server.sendPacket( user.uid, chat )
    if ( var == "color" ):
        tuser.status = int(val)
    elif ( var == "name" ):
        tuser.nick = val
    elif ( var == "icon" ):
        tuser.icon = int(val)
    server.dispatchPacket( tuser.uid , HLPacket(HTLC_HDR_USER_CHANGE) )
