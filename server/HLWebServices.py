from twisted.web import xmlrpc , server
from twisted.internet import reactor
from shared.HLTypes import *
from config import *
from xmlrpclib import Binary
import time

class HLWebServices( xmlrpc.XMLRPC ):
    """ XML-RPC server for live access to server information. """
    
    def __init__( self , hlserver ):
        xmlrpc.XMLRPC.__init__( self )
        self.server = hlserver
        if ENABLE_XMLRPC:
            reactor.listenTCP( XMLRPC_PORT , server.Site( self ) )
    
    def xmlrpc_getServerUptime( self ):
        """ Returns the server uptime in seconds. """
        return long( time.time() - self.server.startTime )
    
    def xmlrpc_getUserlist( self ):
        """ Returns a list of online users. Each entry is a dictionary containing user information. """
        list = []
        for user in self.server.getOrderedUserlist():
            info = {
                "uid": user.uid ,
                "nickname": user.nick ,
                "status": user.status ,
                "icon": user.icon ,
                "color": user.color ,
                "ip": user.ip
            }
            list.append( info )
        return list
    
    def xmlrpc_getUserIcon( self , uid ):
        """ Returns a binary data object containing the GIF icon for the specified user, if one exists. """
        user = self.server.getUser( uid )
        if user != None:
            return Binary( user.gif )
        else:
            return ""
