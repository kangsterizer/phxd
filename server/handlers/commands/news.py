from __future__ import absolute_import
from shared.HLProtocol import *
from server.handlers.NewsHandler import *

def handle( server , user , arg , ref ):
    if len( arg ) > 0:
        limit = int( arg )
    else:
        limit = 100
    
    news = ""
    posts = server.database.loadNewsPosts( limit )
    for post in posts:
        news += formatPost( post )
    news = news[0:65535]
    
    packet = HLPacket( HTLS_HDR_MSG )
    packet.addNumber( DATA_UID , 0 )
    packet.addString( DATA_STRING , news )
    server.sendPacket( user.uid , packet )
