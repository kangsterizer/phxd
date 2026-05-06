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
        # Hotline 1.5+ banner download — ack with empty TASK so the client
        # treats "no banner" as success and stops asking. Implementing a
        # real banner would require its own file-transfer dance.
        self.registerHandlerFunction( HTLC_HDR_DOWNLOAD_BANNER , self.handleDownloadBanner )
        # The "I clicked Agree" reply. Our handleLogin already broadcasts
        # the user-join, so all this needs to do is ack — the client
        # uses the ack as the cue to enable Chat / Files / News tabs.
        self.registerHandlerFunction( HTLC_HDR_AGREED , self.handleAgreed )
    
    def handleUserDisconnected( self , server , user ):
        if user.isLoggedIn():
            leave = HLPacket( HTLS_HDR_USER_LEAVE )
            leave.addNumber( DATA_UID , user.uid )
            server.broadcastPacket( leave )
    
    def handleLogin( self , server , user , packet ):
        if user.isLoggedIn():
            raise HLException( "You are already logged in." , False)

        # Diagnostics: dump every object so we can see exactly what the
        # client sent (type, size, hex). Helpful when porting against
        # third-party clients whose framing might differ subtly.
        try:
            for obj in packet.objs:
                hex_data = obj.data.hex() if isinstance( obj.data , (bytes , bytearray) ) else repr( obj.data )
                server.log.debug(
                    "  login pkt obj type=0x%04x len=%d data=%s" ,
                    obj.type , len( obj.data ) , hex_data ,
                )
        except Exception:
            pass

        # ``DATA_LOGIN`` and ``DATA_PASSWORD`` carry XOR-encoded raw bytes,
        # not text — use ``getBinary``. ``HLDecode`` auto-detects the
        # client's XOR mask (0xFF for classic clients, 0x7F for the
        # Mierau Swift client) and returns plaintext ``bytes``. The login
        # goes to the account DB which stores ``str``, so decode it; the
        # password stays bytes for md5.
        raw_login_wire = packet.getBinary( DATA_LOGIN , HLEncode( "guest" ) )
        raw_pass_wire  = packet.getBinary( DATA_PASSWORD , b"" )
        login_bytes = HLDecode( raw_login_wire )
        password = HLDecode( raw_pass_wire )
        # Some Hotline-1.x-era clients use the documented ``XOR 0xFF`` for
        # logins/passwords; if a particular client doesn't, the decoded
        # bytes won't match a real login. Log the hex of both the wire form
        # and the post-HLEncode form so any encoding mismatch is obvious.
        try:
            server.log.debug(
                "handleLogin wire bytes  login=%s password=%s" ,
                raw_login_wire.hex() , raw_pass_wire.hex() ,
            )
            server.log.debug(
                "handleLogin decoded     login=%s password=<%d bytes>" ,
                login_bytes.hex() , len( password ) ,
            )
        except Exception:
            pass
        login = login_bytes.decode( 'mac-roman' , errors = 'replace' ) if isinstance( login_bytes , (bytes , bytearray) ) else login_bytes

        server.log.debug( "handleLogin: connID-side login=%r ip=%s" , login , user.ip )

        reason = server.checkForBan( user.ip )

        if reason != None:
            raise HLException( "You are banned: %s" % reason , True)

        user.account = server.database.loadAccount( login )
        if user.account == None:
            server.log.info( "Login failed: account %r not found" , login )
            raise HLException( "Login is incorrect." , True)
        # ``HLEncode`` always returns ``bytes`` (the on-the-wire form)
        # post-port, so feed those directly to md5.
        password_for_hash = password if isinstance( password , (bytes , bytearray) ) else password.encode( 'mac-roman' )
        if user.account.password != md5( password_for_hash ).hexdigest():
            nick_raw = packet.getString( DATA_NICK , "unnamed" )
            if isinstance( nick_raw , (bytes , bytearray) ):
                nick_raw = nick_raw.decode( 'mac-roman' )
            user.nick = nick_raw

            server.logEvent( LOG_TYPE_LOGIN , "Login failure" , user )
            server.log.info( "Login failed: bad password for %r (got md5=%s, want=%s)" , login , md5( password_for_hash ).hexdigest() , user.account.password )
            raise HLException( "Password is incorrect." , True)
        if user.account.fileRoot == "":
            user.account.fileRoot = FILE_ROOT
        
        self.handleUserChange( server , user , packet )
        
        # The login reply must carry the user's privileges back to the
        # client. Without ``DATA_PRIVS`` here, the classic 1.9 client
        # assumes zero privs and gates every admin menu item client-side
        # — "Administer Accounts," "Broadcast," etc. all just play an
        # error sound and never send a packet to the server. The
        # original Py2 server omitted this field; clients must have
        # been pulling privs from somewhere else, but the canonical
        # path is the login response. Send as int64 to match the
        # account-read reply's encoding.
        info = HLPacket( HTLS_HDR_TASK , packet.seq )
        info.addString( DATA_SERVERNAME , SERVER_NAME )
        info.addInt64( DATA_PRIVS , user.account.privs )
        info.addInt16( DATA_UID , user.uid )
        info.addInt16( DATA_VERSION , 151 )
        server.sendPacket( user.uid , info )
        # Push the connection agreement immediately after the login ack.
        # The classic 1.9 client (and the Mierau Swift client) blocks
        # the Chat/Files/News tabs until this push arrives, even when
        # the body is empty or the user has PRIV_NO_AGREEMENT. Read the
        # text from the configured file each login so admins can edit
        # the agreement without restarting the server. If the file is
        # missing or unreadable, push an empty agreement so the client
        # at least unblocks.
        try:
            with open( SERVER_AGREEMENT_PATH , "rb" ) as fp:
                agreement_bytes = fp.read()
        except ( IOError , OSError ) as e:
            server.log.warning(
                "agreement file %r unreadable (%s) — pushing empty agreement" ,
                SERVER_AGREEMENT_PATH , e ,
            )
            agreement_bytes = b""
        agreement = HLPacket( HTLS_HDR_SHOW_AGREEMENT )
        agreement.addBinary( DATA_STRING , agreement_bytes )
        server.sendPacket( user.uid , agreement )
        server.logEvent( LOG_TYPE_LOGIN , "Login successful" , user )
        server.database.updateAccountStats( login , 0 , 0 , True )

        # Set this after login, so the user does not get their own join packet.
        # link user.valid = True
        server.handleUserLogin( user ) #link
    
        if user.isIRC:
            ( c , u ) = server.clients[user.uid]
            user.nick = user.nick.replace( " " , "_" )

            c.transport.write(
                ( ":%s!~%s@localhost JOIN :#public\r\n" % (user.nick, user.nick) ).encode( 'mac-roman' )
            )
            userlist = server.getOrderedUserlist()
            nicks = ""
            for myuser in userlist:
                if myuser.uid != user.uid:
                    nicks += " "+ircCheckUserNick( myuser )
            data = ":"+IRC_SERVER_NAME+" 353 "+user.nick+" = #public :"+ircCheckUserNick( user )+nicks+"\r\n"
            data += ":"+IRC_SERVER_NAME+" 366 "+user.nick+" #public :End of /NAMES list.\r\n"
            data += "NOTICE AUTH:*** You have been successfull logged in !\r\n"
            data += "NOTICE *:*** You have been forced to join #public\r\n"
            c.transport.write( data.encode( 'mac-roman' ) )
        
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
        
        # Format the user's idle time. Use floor-division so each
        # component stays an int — Py3's ``/`` on ints returns float.
        secs = int( time.time() - u.lastPacketTime )
        days = secs // 86400
        secs -= ( days * 86400 )
        hours = secs // 3600
        secs -= ( hours * 3600 )
        mins = secs // 60
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
            speed = "%dk/sec" % ( xfer.getTotalBPS() // 1024 )
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

    def handleDownloadBanner( self , server , user , packet ):
        """ Stub for Hotline 1.5+ banner download. We don't host a banner,
        so reply with an empty successful TASK and let the client move on.
        """
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )

    def handleAgreed( self , server , user , packet ):
        """ Client→server confirmation that the user clicked Agree on the
        connection agreement modal. Our login flow already broadcasts
        the user-join, so this is just an ack — the client uses our
        TASK reply as the cue to enable Chat / Files / News. The packet
        also carries the user's chosen nick / icon / status — apply
        them in case they differ from what we read out of the LOGIN
        packet earlier (some clients send placeholders in LOGIN and
        only commit final values in AGREED).
        """
        # If the AGREED packet carries nick/icon, treat it like a
        # USER_CHANGE so any updates broadcast correctly.
        if packet.getString( DATA_NICK , None ) is not None:
            self.handleUserChange( server , user , packet )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
