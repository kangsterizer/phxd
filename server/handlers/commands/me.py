from shared.HLProtocol import *

def handle( server , user , args , ref ):
    chat = HLPacket( HTLC_HDR_CHAT )
    chat.addString( DATA_STRING , args )
    chat.addNumber( DATA_OPTION , 1 )
    if ref > 0:
        chat.addInt32( DATA_CHATID , ref )
    # Call dispatchPacket to re-dispatch it to ChatHandler
    server.dispatchPacket( user.uid , chat )
