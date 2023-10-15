from __future__ import absolute_import
from shared.HLProtocol import *
from shared.HLUtils import *
from shared.HLTypes import *
from config import *
from hashlib import md5
import time

def installHandler( server ):
    server.registerPacketHandler( UserHandler() )

class UserHandler( HLPacketHandler ):
    def __init__( self ):
        HLPacketHandler.__init__( self )
        self.registerHandlerFunction( HTLC_HDR_LOGIN , self.handleLogin )
        self.registerHandlerFunction( HTLC_HDR_USER_CHANGE , self.handleUserChange )
        self.registerHandlerFunction( HTLC_HDR_USER_LIST , self.handleUserList )
        self.registerHandlerFunction( HTLC_HDR_USER_INFO , self.handleUserInfo )
        self.registerHandlerFunction( HTLC_HDR_MSG , self.handleMessage )
        self.registerHandlerFunction( HTLC_HDR_KICK , self.handleUserKick )
        self.registerHandlerFunction( HTLC_HDR_BROADCAST , self.handleBroadcast )
        self.registerHandlerFunction( HTLC_HDR_PING , self.handlePing )
    
    def handleUserDisconnected( self , server , user ):
        if user.isLoggedIn():
            leave = HLPacket( HTLS_HDR_USER_LEAVE )
            leave.addNumber( DATA_UID , user.uid )
            server.broadcastPacket( leave )
    
    def handleLogin( self , server , user , packet ):
        if user.isLoggedIn():
            raise HLException( "You are already logged in." , False)

        login = HLEncode( packet.getString( DATA_LOGIN , HLEncode( "guest" ) ) )
        password = HLEncode( packet.getString( DATA_PASSWORD , "" ) )
        reason = server.checkForBan( user.ip )
        
        if reason != None:
            raise HLException( "You are banned: %s" % reason , True)
        
        user.account = server.database.loadAccount( login )
        if user.account == None:
            raise HLException( "Login is incorrect." , True)
        if user.account.password != md5( password.encode('mac-roman') ).hexdigest():
            user.nick = packet.getString( DATA_NICK , "unnamed" )
    
            server.logEvent( LOG_TYPE_LOGIN , "Login failure" , user )
            raise HLException( "Password is incorrect." , True)
        if user.account.fileRoot == "":
            user.account.fileRoot = FILE_ROOT
        
        self.handleUserChange( server , user , packet )
        
        info = HLPacket( HTLS_HDR_TASK , packet.seq )
        info.addString( DATA_SERVERNAME , SERVER_NAME )
        server.sendPacket( user.uid , info )
        server.logEvent( LOG_TYPE_LOGIN , "Login successful" , user )
        server.database.updateAccountStats( login , 0 , 0 , True )

        # Set this after login, so the user does not get their own join packet.
        # link user.valid = True
        server.handleUserLogin( user ) #link
    
        if user.isIRC:
            ( c , u ) = server.clients[user.uid]
            user.nick = user.nick.replace( " " , "_" )
        
            c.transport.write ( ":%s!~%s@localhost JOIN :#public\r\n" % (user.nick, user.nick) )
            userlist = server.getOrderedUserlist()
            nicks = ""
            for myuser in userlist:
                if myuser.uid != user.uid:
                    nicks += " "+ircCheckUserNick( myuser )
            data = ":"+IRC_SERVER_NAME+" 353 "+user.nick+" = #public :"+ircCheckUserNick( user )+nicks+"\r\n"
            data += ":"+IRC_SERVER_NAME+" 366 "+user.nick+" #public :End of /NAMES list.\r\n"
            data += "NOTICE AUTH:*** You have been successfull logged in !\r\n"
            data += "NOTICE *:*** You have been forced to join #public\r\n"
            c.transport.write( data )
        
        # show welcome msg, needs script support in exec/login !!!
        ret = ""
        ret = shell_exec( user , 'login', '')
        if ret != None:
            chat = HLPacket( HTLS_HDR_CHAT )
            chat.addString( DATA_STRING , ret )
            server.sendPacket( user.uid , chat )
    
    def handleUserChange( self , server , user , packet ):
        oldnick = user.nick
        user.nick = packet.getString( DATA_NICK , user.nick )
        user.icon = packet.getNumber( DATA_ICON , user.icon )
        user.color = packet.getNumber( DATA_COLOR , user.color )
        
        # Limit nickname length.
        user.nick = user.nick[:MAX_NICK_LEN]
        
        # Set their admin status according to their kick priv.
        #if user.hasPriv( PRIV_KICK_USERS ):
        #   user.status |= STATUS_ADMIN
        #else:
        #   user.status &= ~STATUS_ADMIN
        
        # Check to see if they can use any name; if not, set their nickname to their account name.
        if not user.hasPriv( PRIV_USE_ANY_NAME ):
            user.nick = user.account.name
        
        change = HLPacket( HTLS_HDR_USER_CHANGE )
        change.addNumber( DATA_UID , user.uid )
        change.addString( DATA_NICK , user.nick )
        change.addNumber( DATA_ICON , user.icon )
        change.addNumber( DATA_STATUS , user.status )
        change.addString ( DATA_IRC_OLD_NICK , oldnick )
        if user.color >= 0:
            change.addInt32( DATA_COLOR , user.color )
        
        server.broadcastPacket( change )    
    
    def handleUserList( self , server , user , packet ):
        list = HLPacket( HTLS_HDR_TASK , packet.seq )
        for u in server.getOrderedUserlist():
            list.addBinary( DATA_USER , u.flatten() )
        server.sendPacket( user.uid , list )

    def handleUserInfo( self , server , user , packet ):
        uid = packet.getNumber( DATA_UID , 0 )
        u = server.getUser( uid )
        
        if not user.hasPriv( PRIV_USER_INFO ) and ( uid != user.uid ):
            raise HLException("You cannot view user information.")
        if u == None:
            raise HLException("Invalid user.")
        
        # Format the user's idle time.
        secs = int( time.time() - u.lastPacketTime )
        days = secs / 86400
        secs -= ( days * 86400 )
        hours = secs / 3600
        secs -= ( hours * 3600 )
        mins = secs / 60
        secs -= ( mins * 60 )
        idle = ""
        if days > 0:
            idle = "%d:%02d:%02d:%02d" % ( days , hours , mins , secs )
        else:
            idle = "%02d:%02d:%02d" % ( hours , mins , secs )
        if u.isIRC:
            proto = "IRC"
        else:
            proto = "Hotline"
        str = "nickname: %s\r     uid: %s\r   login: %s\rrealname: %s\r   proto: %s\r address: %s\r    idle: %s\r" % ( u.nick , u.uid , u.account.login , u.account.name , proto , u.ip , idle )
        str += "--------------------------------\r"
        xfers = server.fileserver.findTransfersForUser( uid )
        for xfer in xfers:
            type = ( "[DL]" , "[UL]" )[xfer.type]
            speed = "%dk/sec" % ( xfer.getTotalBPS() / 1024 )
            str += "%s %-27.27s\r     %d%% @ %s\r" % ( type , xfer.name , xfer.overallPercent() , speed )
        if len( xfers ) == 0:
            str += "No file transfers.\r"
        str += "--------------------------------\r"
        
        info = HLPacket( HTLS_HDR_TASK , packet.seq )
        info.addNumber( DATA_UID , u.uid )
        info.addString( DATA_NICK , u.nick )
        info.addString( DATA_STRING , str )
        server.sendPacket( user.uid , info )
    
    def handleMessage( self , server , user , packet ):
        uid = packet.getNumber( DATA_UID , 0 )
        str = packet.getString( DATA_STRING , "" )
        
        if not user.hasPriv( PRIV_SEND_MESSAGES ):
            raise HLException("You are not allowed to send messages.")
        if server.getUser( uid ) == None:
            raise HLException("Invalid user.")
        
        msg = HLPacket( HTLS_HDR_MSG )
        msg.addNumber( DATA_UID , user.uid )
        msg.addString( DATA_NICK , user.nick )
        msg.addString( DATA_STRING , str )
        server.sendPacket( uid , msg )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
    
    def handleUserKick( self , server , user , packet ):
        uid = packet.getNumber( DATA_UID , 0 )
        ban = packet.getNumber( DATA_BAN , 0 )
        who = server.getUser( uid )
        
        if not user.hasPriv( PRIV_KICK_USERS ):
            raise HLException("You are not allowed to disconnect users.")
        if who == None:
            raise HLException("Invalid user.")
        if who.account.login != user.account.login and who.hasPriv( PRIV_KICK_PROTECT ):
            raise HLException("%s cannot be disconnected." % who.nick)
        
        action = "Kicked"
        if ban > 0:
            action = "Banned"
            server.addTempBan( who.ip , "Temporary ban." )
        
        server.disconnectUser( uid )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
        server.logEvent( LOG_TYPE_USER , "%s %s [%s]" % ( action , who.nick , who.account.login ) , user )
    
    def handleBroadcast( self , server , user , packet ):
        str = packet.getString( DATA_STRING , "" )
        if not user.hasPriv( PRIV_BROADCAST ):
            raise HLException("You cannot broadcast messages.")
        broadcast = HLPacket( HTLS_HDR_BROADCAST )
        broadcast.addString( DATA_STRING , str )
        server.broadcastPacket( broadcast )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
    
    def handlePing( self , server , user , packet ):
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_PING , packet.seq ) )
