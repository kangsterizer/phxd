from shared.HLProtocol import *
from shared.HLTypes import *
from shared.HLUtils import *
from config import *
import os , time

def installHandler( server ):
	server.registerPacketHandler( ChatHandler() )

def dispatchCommand( server , user , line , ref ):
	""" Dispatch a line of chat to the appropriate chat command handler. """
	if ( line[0] == '/' ) or ( line[0] == '\\' ) or ( user.isIRC and line[0] == '!' ):
		parts = line.split( None , 1 )
		cmd = parts[0][1:]
		args = ""
		if len( parts ) > 1:
			args = parts[1]
		try:
			mod = __import__( "server.handlers.commands.%s" % cmd , None , None , "server.handlers.commands" )
			handler = getattr( mod , "handle" )
			handler( server , user , args , ref )
			return True
		except ImportError:
			#Default handler is server exec kang
			ret = shell_exec( user, cmd, args )
			if( ret == None ):
				return False
			chat = HLPacket( HTLS_HDR_CHAT )
			chat.addString( DATA_STRING, ret )
			server.sendPacket( user.uid, chat )
			return True
	return False

def logChat( chat , user ):
	if not os.path.exists( LOG_DIR ):
		return
	timestamp = time.localtime()
	fname = "%04d-%02d-%02d.txt" % ( timestamp[0] , timestamp[1] , timestamp[2] )
	path = os.path.join( LOG_DIR , fname )
	out = file( path , "a" )
	line = "%02d:%02d:%02d\t%s\t%s\t%s\n" % ( timestamp[3] , timestamp[4] , timestamp[5] , user.account.login , user.nick , chat )
	out.write( line )
	out.close()

class ChatHandler( HLPacketHandler ):
	def __init__( self ):
		HLPacketHandler.__init__( self )
		self.registerHandlerFunction( HTLC_HDR_CHAT , self.handleChat )
		self.registerHandlerFunction( HTLC_HDR_CHAT_CREATE , self.handleChatCreate )
		self.registerHandlerFunction( HTLC_HDR_CHAT_INVITE , self.handleChatInvite )
		self.registerHandlerFunction( HTLC_HDR_CHAT_DECLINE , self.handleChatDecline )
		self.registerHandlerFunction( HTLC_HDR_CHAT_JOIN , self.handleChatJoin )
		self.registerHandlerFunction( HTLC_HDR_CHAT_LEAVE , self.handleChatLeave )
		self.registerHandlerFunction( HTLC_HDR_CHAT_SUBJECT , self.handleChatSubject )
	
	def handleUserDisconnected( self , server , user ):
		deadChats = []
		
		# go through all the private chats removing this user
		# keep a list of dead chats to remove them all at once
		for chat in server.chats.values():
			if chat.hasInvite( user ):
				chat.removeInvite( user )
			if chat.hasUser( user ):
				chat.removeUser( user )
				if len( chat.users ) > 0:
					# Send a chat leave to everyone left in the chat.
					leave = HLPacket( HTLS_HDR_CHAT_USER_LEAVE )
					leave.addInt32( DATA_CHATID , chat.id )
					leave.addNumber( DATA_UID , user.uid )
					for u in chat.users:
						server.sendPacket( u.uid , leave )
				else:
					# Otherwise, mark the chat as dead.
					deadChats.append( chat.id )
		
		# Now we can remove all the dead chats without modifying the list we were iterating through.
		for dead in deadChats:
			server.removeChat( dead )
	
	def handleChat( self , server , user , packet ):
		str = packet.getString( DATA_STRING , "" )
		opt = packet.getNumber( DATA_OPTION , 0 )
		ref = packet.getNumber( DATA_CHATID , 0 )
		pchat = server.getChat( ref )
		
		if user.hasPriv( PRIV_SEND_CHAT ) and ( len( str ) > 0 ):
			str = str.replace( "\n" , "\r" )
			lines = str.split( "\r" )
			format = ( CHAT_FORMAT , EMOTE_FORMAT )[( opt > 0 )]
			for lineStr in lines:
				line = lineStr[:MAX_CHAT_LEN]
				if ( len( line ) > 0 ) and ( not dispatchCommand( server , user , line , ref ) ):
					f_str = format % ( user.nick , line )
					chat = HLPacket( HTLS_HDR_CHAT )
					chat.addNumber( DATA_UID , user.uid )
					chat.addString( DATA_STRING , f_str )
					if pchat != None:
						# If this is meant for a private chat, add the chat ID
						# and send it to everyone in the chat.
						chat.addInt32( DATA_CHATID , pchat.id )
						for u in pchat.users:
							server.sendPacket( u.uid , chat )
					else:
						# Otherwise, send it to public chat (and log it).
						server.broadcastPacket( chat , PRIV_READ_CHAT )
						if LOG_CHAT:
							logChat( line , user )
	
	def handleChatCreate( self , server , user , packet ):
		uid = packet.getNumber( DATA_UID , 0 )
		who = server.getUser( uid )
		
		if not user.hasPriv( PRIV_CREATE_CHATS ):
			raise HLException , "You cannot create private chats."
		
		# First, create the new chat, adding the user.
		chat = server.createChat()
		chat.addUser( user )
		
		# Send the completed task with user info.
		reply = HLPacket( HTLS_HDR_TASK , packet.seq )
		reply.addInt32( DATA_CHATID , chat.id )
		reply.addNumber( DATA_UID , user.uid )
		reply.addString( DATA_NICK , user.nick )
		reply.addNumber( DATA_ICON , user.icon )
		reply.addNumber( DATA_STATUS , user.status )
		if user.color >= 0L:
			reply.addInt32( DATA_COLOR , user.color )
		server.sendPacket( user.uid , reply )
		
		if ( who != None ) and ( who.uid != user.uid ):
			# Add the specified user to the invite list.
			chat.addInvite( who )
			
			# Invite the specified user to the newly created chat.
			invite = HLPacket( HTLS_HDR_CHAT_INVITE )
			invite.addInt32( DATA_CHATID , chat.id )
			invite.addNumber( DATA_UID , user.uid )
			invite.addString( DATA_NICK , user.nick )
			server.sendPacket( uid , invite )
	
	def handleChatInvite( self , server , user , packet ):
		ref = packet.getNumber( DATA_CHATID , 0 )
		uid = packet.getNumber( DATA_UID , 0 )
		chat = server.getChat( ref )
		who = server.getUser( uid )
		
		if who == None:
			raise HLException , "Invalid user."
		if chat == None:
			raise HLException , "Invalid chat."
		if uid == user.uid:
			# Ignore self invitations.
			return
		if chat.hasInvite( who ):
			# Ignore all invitations after the first.
			return
		if not chat.hasUser( user ):
			raise HLException , "You are not in this chat."
		if chat.hasUser( who ):
			# The specified user is already in the chat.
			return
		
		chat.addInvite( who )
		
		# Send the invitation to the specified user.
		invite = HLPacket( HTLS_HDR_CHAT_INVITE )
		invite.addInt32( DATA_CHATID , chat.id )
		invite.addNumber( DATA_UID , user.uid )
		invite.addString( DATA_NICK , user.nick )
		server.sendPacket( who.uid , invite )
	
	def handleChatDecline( self , server , user , packet ):
		ref = packet.getNumber( DATA_CHATID , 0 )
		chat = server.getChat( ref )
		if ( chat != None ) and chat.hasInvite( user ):
			chat.removeInvite( user )
			str = "\r< %s has declined the invitation to chat >" % user.nick
			decline = HLPacket( HTLS_HDR_CHAT )
			decline.addInt32( DATA_CHATID , chat.id )
			decline.addString( DATA_STRING , str )
			for u in chat.users:
				server.sendPacket( u.uid , decline )
	
	def handleChatJoin( self , server , user , packet ):
		ref = packet.getNumber( DATA_CHATID , 0 )
		chat = server.getChat( ref )
		
		if chat == None:
			raise HLException , "Invalid chat."
		if not chat.hasInvite( user ):
			raise HLException , "You were not invited to this chat."
		
		# Send a join packet to everyone in the chat.
		join = HLPacket( HTLS_HDR_CHAT_USER_CHANGE )
		join.addInt32( DATA_CHATID , chat.id )
		join.addNumber( DATA_UID , user.uid )
		join.addString( DATA_NICK , user.nick )
		join.addNumber( DATA_ICON , user.icon )
		join.addNumber( DATA_STATUS , user.status )
		if user.color >= 0L:
			join.addInt32( DATA_COLOR , user.color )
		for u in chat.users:
			server.sendPacket( u.uid , join )
		
		# Add the joiner to the chat.
		chat.addUser( user )
		chat.removeInvite( user )
		
		# Send the userlist back to the joiner.
		list = HLPacket( HTLS_HDR_TASK , packet.seq )
		for u in chat.users:
			list.addBinary( DATA_USER , u.flatten() )
		list.addString( DATA_SUBJECT , chat.subject )
		server.sendPacket( user.uid , list )
	
	def handleChatLeave( self , server , user , packet ):
		ref = packet.getNumber( DATA_CHATID , 0 )
		chat = server.getChat( ref )
		
		if ( chat == None ) or ( not chat.hasUser( user ) ):
			return
		
		chat.removeUser( user )
		if len( chat.users ) > 0:
			leave = HLPacket( HTLS_HDR_CHAT_USER_LEAVE )
			leave.addInt32( DATA_CHATID , chat.id )
			leave.addNumber( DATA_UID , user.uid )
			for u in chat.users:
				server.sendPacket( u.uid , leave )
		else:
			server.removeChat( chat.id )
	
	def handleChatSubject( self , server , user , packet ):
		ref = packet.getNumber( DATA_CHATID , 0 )
		sub = packet.getString( DATA_SUBJECT , "" )
		chat = server.getChat( ref )
		if chat != None:
			subject = HLPacket( HTLS_HDR_CHAT_SUBJECT )
			subject.addInt32( DATA_CHATID , ref )
			subject.addString( DATA_SUBJECT , sub )
			for u in chat.users:
				server.sendPacket( u.uid , subject )
