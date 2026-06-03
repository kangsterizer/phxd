from __future__ import absolute_import
from shared.HLProtocol import *
from shared.HLTypes import *
from config import *
from struct import pack , unpack
from hashlib import md5


def _flatten_subfield( tag , data ):
    """ Serialize a sub-field as ``tag(2) | len(2) | data`` — matching
    HLObject.flatten but used inside the per-account blob. """
    if isinstance( data , str ):
        data = data.encode( 'mac-roman' )
    return pack( "!HH" , tag , len( data ) ) + data


def _parse_subfields( blob ):
    """ Parse a serialized sub-packet — ``[2-byte field count]
    [tag(2) | len(2) | data]*`` — into a dict mapping tag → raw bytes.
    Used for the inner per-user record inside a TranUpdateUser request. """
    if len( blob ) < 2:
        return {}
    count = unpack( "!H" , blob[0:2] )[0]
    fields = {}
    pos = 2
    for _ in range( count ):
        if pos + 4 > len( blob ):
            break
        tag , size = unpack( "!HH" , blob[pos:pos+4] )
        pos += 4
        if pos + size > len( blob ):
            break
        fields[tag] = blob[pos:pos+size]
        pos += size
    return fields


def _to_bytes( s ):
    """ md5 in Py3 wants bytes; tolerate ``str`` callers. """
    if isinstance( s , (bytes , bytearray) ):
        return s
    return s.encode( 'mac-roman' )

def _to_str( s ):
    """ HLDecode returns bytes; account files / DB lookups / log lines all
    want str. Decode via mac-roman (Hotline's text encoding). Without this,
    ``"%s" % b'toiletj'`` writes the literal repr ``"b'toiletj'"`` into the
    accounts file and every later lookup misses. """
    if isinstance( s , (bytes , bytearray) ):
        return s.decode( 'mac-roman' )
    return s

def installHandler( server ):
    server.registerPacketHandler( AcctHandler() )

class AcctHandler( HLPacketHandler ):
    def __init__( self ):
        HLPacketHandler.__init__( self )
        self.registerHandlerFunction( HTLC_HDR_ACCOUNT_READ , self.handleAccountRead )
        self.registerHandlerFunction( HTLC_HDR_ACCOUNT_MODIFY , self.handleAccountModify )
        self.registerHandlerFunction( HTLC_HDR_ACCOUNT_CREATE , self.handleAccountCreate )
        self.registerHandlerFunction( HTLC_HDR_ACCOUNT_DELETE , self.handleAccountDelete )
        self.registerHandlerFunction( HTLC_HDR_ACCOUNT_LIST , self.handleAccountList )
        self.registerHandlerFunction( HTLC_HDR_ACCOUNT_UPDATE , self.handleAccountUpdate )
    
    def handleAccountRead( self , server , user , packet ):
        # Wire login is XOR-encoded just like every other DATA_LOGIN field,
        # so it must be HLDecode'd before we hit the database. The original
        # Py2 code skipped this step and got away with it because str/bytes
        # were interchangeable; Py3 silently looks up the encoded gibberish
        # and returns None → "Error loading account."
        login = _to_str( HLDecode( packet.getBinary( DATA_LOGIN , b"" ) ) )

        acct = server.database.loadAccount( login )
        if not user.hasPriv( PRIV_READ_USERS ):
            raise HLException("You cannot read accounts.")
        if acct == None:
            raise HLException("Error loading account.")
        
        reply = HLPacket( HTLS_HDR_TASK , packet.seq )
        reply.addString( DATA_LOGIN , HLEncode( acct.login ) )
        reply.addString( DATA_PASSWORD , HLEncode( acct.password ) )
        reply.addString( DATA_NICK , acct.name )
        reply.addInt64( DATA_PRIVS , acct.privs )
        server.sendPacket( user.uid , reply )
    
    def handleAccountModify( self , server , user , packet ):
        login = _to_str( HLDecode( packet.getBinary( DATA_LOGIN , b"" ) ) )
        passwd = HLDecode( packet.getBinary( DATA_PASSWORD , b"" ) )
        name = packet.getString( DATA_NICK , "" )
        privs = packet.getNumber( DATA_PRIVS , 0 )
        
        acct = server.database.loadAccount( login )
        if not user.hasPriv( PRIV_MODIFY_USERS ):
            raise HLException("You cannot modify accounts.")
        if acct == None:
            raise HLException("Invalid account.")
        
        acct.name = name
        acct.privs = privs
        # The "no change" sentinel is a single 0xFF byte (HLEncode of "")
        # — match it as bytes since ``HLEncode`` returns ``bytes`` now.
        if passwd != b"\xFF" and passwd != "\xFF":
            acct.password = md5( _to_bytes( passwd ) ).hexdigest()
        server.database.saveAccount( acct )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
        server.updateAccounts( acct )
        server.logEvent( LOG_TYPE_ACCOUNT , "Modified account %s." % login , user )
    
    def handleAccountCreate( self , server , user , packet ):
        login = _to_str( HLDecode( packet.getBinary( DATA_LOGIN , b"" ) ) )
        passwd = HLDecode( packet.getBinary( DATA_PASSWORD , b"" ) )
        name = packet.getString( DATA_NICK , "" )
        privs = packet.getNumber( DATA_PRIVS , 0 )
        
        if not user.hasPriv( PRIV_CREATE_USERS ):
            raise HLException("You cannot create accounts.")
        if server.database.loadAccount( login ) != None:
            raise HLException("Login already exists.")
        
        acct = HLAccount( login )
        acct.password = md5( _to_bytes( passwd ) ).hexdigest()
        acct.name = name
        acct.privs = privs
        
        server.database.saveAccount( acct )
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
        server.logEvent( LOG_TYPE_ACCOUNT , "Created account %s." % login , user )
    
    def handleAccountDelete( self , server , user , packet ):
        login = _to_str( HLDecode( packet.getBinary( DATA_LOGIN , b"" ) ) )
        if not user.hasPriv( PRIV_DELETE_USERS ):
            raise HLException("You cannot delete accounts.")
        if server.database.deleteAccount( login ) < 1:
            raise HLException("Error deleting account.")
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
        server.logEvent( LOG_TYPE_ACCOUNT , "Deleted account %s." % login , user )

    def handleAccountList( self , server , user , packet ):
        """ Handle tranListUsers (0x15C) — the "Administer Accounts"
        window's first request after it opens. We reply with one
        DATA_STRING (0x65) field per account, each carrying a serialized
        sub-packet (field count + nick/login/privs/password subfields).
        See HTLC_HDR_ACCOUNT_LIST in HLProtocol.py for the wire layout
        and the Mobius cross-reference. """
        if not user.hasPriv( PRIV_READ_USERS ):
            raise HLException( "You cannot list accounts." )
        reply = HLPacket( HTLS_HDR_TASK , packet.seq )
        for acct in server.database.listAccounts():
            sub = b""
            sub += _flatten_subfield( DATA_NICK , acct.name or "" )
            sub += _flatten_subfield( DATA_LOGIN , HLEncode( acct.login ) )
            # DATA_PRIVS is currently emitted as 8 raw bytes via
            # ``addInt64``-equivalent packing; keep parity with
            # handleAccountRead until the priv bit-order question is
            # settled (see TODO).
            sub += _flatten_subfield( DATA_PRIVS , pack( "!Q" , int( acct.privs or 0 ) ) )
            # Match Mobius's behaviour: send DATA_PASSWORD = "x" as a
            # placeholder when a password is set, omit otherwise. The
            # 1.9 client uses presence of the field to decide whether
            # to render the "password is set" indicator.
            if acct.password:
                sub += _flatten_subfield( DATA_PASSWORD , b"x" )
            # field count for the inner sub-packet
            field_count = 3 + ( 1 if acct.password else 0 )
            sub_packet = pack( "!H" , field_count ) + sub
            reply.addBinary( DATA_STRING , sub_packet )
        server.sendPacket( user.uid , reply )

    def handleAccountUpdate( self , server , user , packet ):
        """ Handle tranUpdateUser (0x15D) — the v1.5+ batch editor sends
        one of these for every "Save" click in Administer Accounts. The
        outer transaction carries one DATA_STRING field per user
        operation; each is a serialized sub-packet (see
        HTLC_HDR_ACCOUNT_UPDATE in HLProtocol.py for the wire layout
        and the create/modify/delete/rename detection rules).
        Cross-checked against Mobius HandleUpdateUser
        (reference/mobius/internal/mobius/transaction_handlers.go:740). """
        # The packet may bundle multiple per-user records — process
        # each in order and bail with an HLException at the first
        # priv check failure so the client gets an obvious error.
        records = []
        for obj in packet.objs:
            if obj.type == DATA_STRING:
                records.append( obj.data if isinstance( obj.data , (bytes , bytearray) ) else obj.data.encode( 'mac-roman' ) )
        if not records:
            # Empty update — just ack so the client doesn't hang.
            server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
            return

        for blob in records:
            sub = _parse_subfields( blob )

            # Single-field record = DELETE; the lone field is DATA_STRING
            # carrying the XOR-encoded login.
            if len( sub ) == 1 and DATA_STRING in sub:
                if not user.hasPriv( PRIV_DELETE_USERS ):
                    raise HLException( "You cannot delete accounts." )
                login = _to_str( HLDecode( sub[DATA_STRING] ) )
                if not server.database.deleteAccount( login ):
                    server.log.warning( "delete failed for login %r" , login )
                else:
                    server.logEvent( LOG_TYPE_ACCOUNT , "Deleted account %s." % login , user )
                continue

            # Modify / create / rename. DATA_STRING (if present) carries
            # the *old* login; DATA_LOGIN carries the new/current login.
            new_login = _to_str( HLDecode( sub.get( DATA_LOGIN , b"" ) ) )
            if DATA_STRING in sub:
                target_login = _to_str( HLDecode( sub[DATA_STRING] ) )
            else:
                target_login = new_login

            if not target_login:
                server.log.warning( "tranUpdateUser record had no login — skipping" )
                continue

            existing = server.database.loadAccount( target_login )

            # Pull optional fields once.
            name = sub.get( DATA_NICK , b"" )
            if isinstance( name , (bytes , bytearray) ):
                name = name.decode( 'mac-roman' )
            privs_bytes = sub.get( DATA_PRIVS , None )
            # DATA_PRIVS is 8 raw bytes from the v1.5+ editor — Mobius
            # access-bitmap layout. Stash as uint64 so it round-trips
            # through the existing int-based account schema unchanged.
            privs_int = unpack( "!Q" , privs_bytes )[0] if privs_bytes and len( privs_bytes ) == 8 else None
            password_field = sub.get( DATA_PASSWORD , None )

            if existing is not None:
                # Modify (or rename + modify).
                if not user.hasPriv( PRIV_MODIFY_USERS ):
                    raise HLException( "You cannot modify accounts." )
                # Rename: remove old row and re-insert under the new login.
                # We do this by mutating the in-memory record and
                # round-tripping through delete + create when the login
                # actually changed; otherwise just update in place.
                rename = ( DATA_STRING in sub ) and ( target_login != new_login )

                existing.name = name or existing.name
                if privs_int is not None:
                    existing.privs = privs_int

                # Password semantics — see HTLC_HDR_ACCOUNT_UPDATE comment:
                #   missing      → clear password
                #   single 0x00  → keep existing
                #   anything else → set new password (XOR-decoded first)
                if password_field is None:
                    existing.password = md5( b"" ).hexdigest()
                elif password_field != b"\x00":
                    new_pass = HLDecode( password_field )
                    existing.password = md5( _to_bytes( new_pass ) ).hexdigest()

                if rename:
                    # The text DB keys on login — easiest correct path is
                    # delete-then-recreate. Preserve id by clearing it so
                    # saveAccount re-numbers (the classic 1.9 client
                    # doesn't display the internal id anyway).
                    server.database.deleteAccount( target_login )
                    existing.login = new_login
                    existing.id = 0
                    server.database.saveAccount( existing )
                    server.logEvent( LOG_TYPE_ACCOUNT , "Renamed account %s → %s." % ( target_login , new_login ) , user )
                else:
                    server.database.saveAccount( existing )
                    server.logEvent( LOG_TYPE_ACCOUNT , "Modified account %s." % target_login , user )
                server.updateAccounts( existing )
            else:
                # Create.
                if not user.hasPriv( PRIV_CREATE_USERS ):
                    raise HLException( "You cannot create accounts." )
                acct = HLAccount( new_login )
                acct.name = name
                if privs_int is not None:
                    acct.privs = privs_int
                if password_field is None or password_field == b"\x00":
                    # No password set yet — store hash of empty string,
                    # matching Mobius's "create with empty password" path.
                    acct.password = md5( b"" ).hexdigest()
                else:
                    new_pass = HLDecode( password_field )
                    acct.password = md5( _to_bytes( new_pass ) ).hexdigest()
                server.database.saveAccount( acct )
                server.logEvent( LOG_TYPE_ACCOUNT , "Created account %s." % new_login , user )

        # Acknowledge the whole batch with a single empty TASK reply,
        # matching Mobius's "Fields used in the reply: None" contract.
        server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
