from __future__ import absolute_import
from shared.HLProtocol import HLCharConst
from datetime import datetime
from struct import *
import os
from six.moves import range

LOG_TYPE_GENERAL =  1
LOG_TYPE_LOGIN =    2
LOG_TYPE_USER =     3
LOG_TYPE_ACCOUNT =  4
LOG_TYPE_FILE =     5
LOG_TYPE_TRANSFER = 6
LOG_TYPE_TRACKER =      7
LOG_TYPE_ERROR =    99
LOG_TYPE_DEBUG =    666

LOG_TYPE_STR_MAP = {LOG_TYPE_GENERAL:"GENERAL",
                    LOG_TYPE_LOGIN:"LOGIN",
                    LOG_TYPE_USER:"USER",
                    LOG_TYPE_ACCOUNT:"ACCOUNT",
                    LOG_TYPE_FILE:"FILE",
                    LOG_TYPE_TRANSFER:"TRANSFER",
                    LOG_TYPE_TRACKER:"TRACKER",
                    LOG_TYPE_ERROR:"ERROR",
                    LOG_TYPE_DEBUG:"DEBUG"}

class HLException(Exception):
    """ Exception thrown due to protocol errors. """
    
    def __init__( self , msg = "Unknown exception." , fatal = False ):
        self.msg = msg
        self.fatal = fatal

class HLAccount:
    """ Stores account information. """
    
    def __init__( self , login = "" ):
        self.id = 0
        self.login = login
        self.password = ""
        self.name = "Null Account"
        self.privs = 0
        self.fileRoot = ""
    
    def copyFrom( self , acct ):
        """ Take all instance variables from the specified HLAccount object.
        Useful for updating account information without making a new object. """
        self.id = acct.id
        self.login = acct.login
        self.password = acct.password
        self.name = acct.name
        self.privs = acct.privs
        if acct.fileRoot != "":
            self.fileRoot = acct.fileRoot

class HLUser:
    """ Stores user information, along with an associated HLAccount object. Also flattenable for use in userlist packet objects. """
    
    def __init__( self , uid = 0 , addr = "" ):
        self.uid = uid
        self.ip = addr
        self.nick = "unnamed"
        self.icon = 500
        self.status = 0
        self.gif = ""
        self.color = -1
        self.account = None
        self.away = False
        self.lastPacketTime = 0.0
        self.valid = False
        self.local = True
        self.isIRC = False
    
    def getProtocol( self ):
        """ Returns the protocol used by the client. """
        if self.isIRC:
            return "IRC"
        else:
            return "Hotline"
    
    def isLoggedIn( self ):
        """ Returns True if the user has successfully logged in. """
        return self.valid
    
    def hasPriv( self , priv ):
        """ Returns True if the account associated with the user has the specified privilege. """
        return ( self.account != None ) and ( ( int( self.account.privs ) & priv ) > 0 )
       
    def parse( self, data ):
               if len(data) < 8:
                       return 0
               ( self.uid, self.icon, self.status, nicklen ) = unpack( "!4H", data[0:8] )
               if ( len(data) - 8 ) < nicklen:
                       return 0
               self.nick = data[8:8+nicklen]
               if ( len(data) - 8 - nicklen ) >= 4:
                       self.color = unpack( "!L", data[8+nicklen:12+nicklen] )[0]
                       return ( 12 + nicklen )
               return ( 8 + nicklen )
    
    
    def flatten( self ):
        """ Flattens the user information into a packed structure to send in a HLObject. """
        data = ""
        data += pack( "!4H" , self.uid , self.icon , self.status , len( self.nick ) )
        data += self.nick
        # this is an avaraline extension for nick coloring
        if self.color >= 0:
            data += pack( "!L" , self.color )
        return data

class HLChat:
    """ Stores information about a private chat. """
    
    def __init__( self , id = 0 ):
        self.id = id
        self.users = []
        self.invites = []
        self.subject = ""
    
    def addUser( self , user ):
        """ Adds the specified user to this chat. """
        self.users.append( user )
    
    def addInvite( self , user ):
        """ Adds the specified user to the list of invitees for this chat. """
        self.invites.append( user.uid )
    
    def removeUser( self , user ):
        """ Removes the specified user from this chat. """
        self.users.remove( user )
    
    def removeInvite( self , user ):
        """ Removes the specified user from the list of invitees for this chat. """
        self.invites.remove( user.uid )
    
    def hasUser( self , user ):
        """ Returns True if this chat has the specified user in it. """
        for u in self.users:
            if u.uid == user.uid:
                return True
        return False
    
    def hasInvite( self , user ):
        """ Returns True if this chat has the specified user in its list of invitees. """
        for uid in self.invites:
            if user.uid == uid:
                return True
        return False

class HLResumeData:
    """ Stores transfer resume data (offsets for each fork type). """
    
    def __init__( self , data = None ):
        self.forkOffsets = {}
        self.forkCount = 0
        if ( data != None ) and ( len( data ) >= 42 ):
            self._parseResumeData( data )
    
    def forkOffset( self , fork ):
        """ Returns the offset for the specified fork type. """
        if fork in self.forkOffsets:
            return self.forkOffsets[fork]
        return 0
    
    def setForkOffset( self , fork , offset ):
        """ Sets the offset for the specified fork type. """
        self.forkOffsets[fork] = offset
    
    def _parseResumeData( self , data ):
        """ Parses the specified packed structure data into this resume data object. """
        ( format , version ) = unpack( "!LH" , data[0:6] )
        _reserved = data[6:40]
        self.forkCount = unpack( "!H" , data[40:42] )[0]
        for k in range( self.forkCount ):
            offset = 42 + ( 16 * k )
            subData = data[offset:offset+8]
            if len( subData ) == 8:
                ( forkType , forkOffset ) = unpack( "!2L" , subData )
                self.forkOffsets[forkType] = forkOffset
    
    def flatten( self ):
        """ Flattens the resume information into a packed structure to send in a HLObject. """
        data = pack( "!LH" , HLCharConst( "RFLT" ) , 1 )
        data += ( "\0" * 34 )
        data += pack( "!H" , len( list(self.forkOffsets.keys()) ) )
        for forkType in self.forkOffsets.keys():
            data += pack( "!4L" , forkType , self.forkOffsets[forkType] , 0 , 0 )
        return data

class HLNewsPost:
    """ Stores information about a single news post. """
    
    def __init__( self , nick = "" , login = "" , post = "" ):
        self.id = 0
        self.nick = nick
        self.login = login
        self.post = post
        now = datetime.now()
        self.date = now.replace( microsecond = 0 )

class HLPacketHandler:
    """ Packet handler base class. Should be overridden to handle actual packets. """
    
    def __init__( self ):
        self._funcs = {}
    
    def registerHandlerFunction( self , type , func ):
        """ Registers the specified function to be called when handling the specified packet type. """
        self._funcs[type] = func
    
    def handleUserConnected( self , server , user ):
        """ Called when a user connects, before any packets are handled. Should be overridden. """
        pass
    
    def handleUserDisconnected( self , server , user ):
        """ Called when a user disconnects. Should be overridden. """
        pass
    
    def handlePacket( self , server , user , packet ):
        """ Default dispatcher called when a packet is received. Calls any registered handler functions. Returns True when packet is handled. """
        if packet.type in self._funcs:
            self._funcs[packet.type]( server , user , packet )
            return True
        return False
