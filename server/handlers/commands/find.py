from __future__ import absolute_import
from shared.HLProtocol import *
import os

def handle( server , user , arg , ref ):
    if len( arg ) > 0:
        pre = len( user.account.fileRoot )
        matches = []
        for ( root , dirs , files ) in os.walk( user.account.fileRoot ):
            for name in dirs:
                if arg.upper() in name.upper():
                    matches.append( "+ " + os.path.join( root , name )[pre:] )
            for name in files:
                if arg.upper() in name.upper():
                    matches.append( "- " + os.path.join( root , name )[pre:] )
        found = "(none)"
        if len( matches ) > 0:
            found = "\r > ".join( matches )
        matchStr = "\r > --- search results for '%s' ------------\r > %s" % ( arg , found )
        chat = HLPacket( HTLS_HDR_CHAT )
        chat.addString( DATA_STRING , matchStr )
        if ref > 0:
            chat.addInt32( DATA_CHATID , ref )
        server.sendPacket( user.uid , chat )
