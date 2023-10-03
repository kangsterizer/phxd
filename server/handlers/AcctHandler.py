from shared.HLProtocol import *
from shared.HLTypes import *
from config import *
from struct import pack
from md5 import md5

def installHandler( server ):
	server.registerPacketHandler( AcctHandler() )

class AcctHandler( HLPacketHandler ):
	def __init__( self ):
		HLPacketHandler.__init__( self )
		self.registerHandlerFunction( HTLC_HDR_ACCOUNT_READ , self.handleAccountRead )
		self.registerHandlerFunction( HTLC_HDR_ACCOUNT_MODIFY , self.handleAccountModify )
		self.registerHandlerFunction( HTLC_HDR_ACCOUNT_CREATE , self.handleAccountCreate )
		self.registerHandlerFunction( HTLC_HDR_ACCOUNT_DELETE , self.handleAccountDelete )
	
	def handleAccountRead( self , server , user , packet ):
		login = packet.getString( DATA_LOGIN , "" )
		
		acct = server.database.loadAccount( login )
		if not user.hasPriv( PRIV_READ_USERS ):
			raise HLException , "You cannot read accounts."
		if acct == None:
			raise HLException , "Error loading account."
		
		reply = HLPacket( HTLS_HDR_TASK , packet.seq )
		reply.addString( DATA_LOGIN , HLEncode( acct.login ) )
		reply.addString( DATA_PASSWORD , HLEncode( acct.password ) )
		reply.addString( DATA_NICK , acct.name )
		reply.addInt64( DATA_PRIVS , acct.privs )
		server.sendPacket( user.uid , reply )
	
	def handleAccountModify( self , server , user , packet ):
		login = HLEncode( packet.getString( DATA_LOGIN , "" ) )
		passwd = HLEncode( packet.getString( DATA_PASSWORD , "" ) )
		name = packet.getString( DATA_NICK , "" )
		privs = packet.getNumber( DATA_PRIVS , 0 )
		
		acct = server.database.loadAccount( login )
		if not user.hasPriv( PRIV_MODIFY_USERS ):
			raise HLException , "You cannot modify accounts."
		if acct == None:
			raise HLException , "Invalid account."
		
		acct.name = name
		acct.privs = privs
		if passwd != "\xFF":
			acct.password = md5( passwd ).hexdigest()
		server.database.saveAccount( acct )
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
		server.updateAccounts( acct )
		server.logEvent( LOG_TYPE_ACCOUNT , "Modified account %s." % login , user )
	
	def handleAccountCreate( self , server , user , packet ):
		login = HLEncode( packet.getString( DATA_LOGIN , "" ) )
		passwd = HLEncode( packet.getString( DATA_PASSWORD , "" ) )
		name = packet.getString( DATA_NICK , "" )
		privs = packet.getNumber( DATA_PRIVS , 0 )
		
		if not user.hasPriv( PRIV_CREATE_USERS ):
			raise HLException , "You cannot create accounts."
		if server.database.loadAccount( login ) != None:
			raise HLException , "Login already exists."
		
		acct = HLAccount( login )
		acct.password = md5( passwd ).hexdigest()
		acct.name = name
		acct.privs = privs
		
		server.database.saveAccount( acct )
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
		server.logEvent( LOG_TYPE_ACCOUNT , "Created account %s." % login , user )
	
	def handleAccountDelete( self , server , user , packet ):
		login = HLEncode( packet.getString( DATA_LOGIN , "" ) )
		if not user.hasPriv( PRIV_DELETE_USERS ):
			raise HLException , "You cannot delete accounts."
		if server.database.deleteAccount( login ) < 1:
			raise HLException , "Error deleting account."
		server.sendPacket( user.uid , HLPacket( HTLS_HDR_TASK , packet.seq ) )
		server.logEvent( LOG_TYPE_ACCOUNT , "Deleted account %s." % login , user )
