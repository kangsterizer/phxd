from __future__ import absolute_import
from __future__ import print_function
from server.HLDatabase import HLDatabase
from shared.HLTypes import *
from config import *
import MySQLdb
from six.moves import range

class MySQLDatabase (HLDatabase):
	""" MySQL-based implementation of HLDatabase. """
	
	def __init__( self ):
		self.db = MySQLdb.connect( host = DB_HOST , user = DB_USER , passwd = DB_PASS , db = DB_NAME )
	
	def loadAccount( self , login ):
		acct = None
		cur = self.db.cursor()
		num = cur.execute( "SELECT id , password , name , privs , fileRoot FROM accounts WHERE login = %s" , login )
		if num > 0:
			acct = HLAccount( login )
			( acct.id , acct.password , acct.name , acct.privs , acct.fileRoot ) = cur.fetchone()
		cur.close()
		return acct
	
	def saveAccount( self , acct ):
		cur = self.db.cursor()
		if acct.id > 0:
			cur.execute( "UPDATE accounts SET password = %s , name = %s , privs = %s , fileRoot = %s WHERE id = %s" , \
				( acct.password , acct.name , acct.privs , acct.fileRoot , acct.id ) )
		else:
			cur.execute( "INSERT INTO accounts ( login , password , name , privs , fileRoot ) VALUES ( %s , %s , %s , %s , %s )" , ( acct.login , acct.password , acct.name , acct.privs , acct.fileRoot ) )
			acct.id = cur.lastrowid
		cur.close()
	
	def deleteAccount( self , login ):
		cur = self.db.cursor()
		num = cur.execute( "DELETE FROM accounts WHERE login = %s" , login )
		cur.close()
		return num > 0
	
	def updateAccountStats( self , login , downloaded , uploaded , setDate = False ):
		cur = self.db.cursor()
		if ( downloaded > 0 ) or ( uploaded > 0 ):
			cur.execute( "UPDATE accounts SET bytesDownloaded = bytesDownloaded + %s , bytesUploaded = bytesUploaded + %s WHERE login = %s" , ( downloaded , uploaded , login ) )
		if setDate:
			cur.execute( "UPDATE accounts SET lastLogin = NOW() WHERE login = %s" , login )
		cur.close()
	
	def loadNewsPosts( self , limit = 0 ):
		posts = []
		query = "SELECT id , nick , login , post , date FROM news ORDER BY date DESC"
		if limit > 0:
			query += " LIMIT %d" % limit
		cur = self.db.cursor()
		num = cur.execute( query )
		for k in range( num ):
			post = HLNewsPost()
			( post.id , post.nick , post.login , post.post , post.date ) = cur.fetchone()
			posts.append( post )
		cur.close()
		return posts
	
	def saveNewsPost( self , post ):
		cur = self.db.cursor()
		if post.id > 0:
			cur.execute( "UPDATE news SET nick = %s , login = %s , post = %s , date = %s WHERE id = %s" , ( post.nick , post.login , post.post , post.date , post.id ) )
		else:
			cur.execute( "INSERT INTO news ( nick , login , post , date ) VALUES ( %s , %s , %s , %s )" , ( post.nick , post.login , post.post , post.date ) )
			post.id = cur.lastrowid
		cur.close()
	
	def checkBanlist( self , addr ):
		reason = None
		try:
			cur = self.db.cursor()
			num = cur.execute( "SELECT reason FROM banlist WHERE address = %s" , addr )
		except:
			print("mysql connection lost. check that mysql is up. reconnecting now.")
			cur = self.db.cursor()
			self.db = MySQLdb.connect( host = DB_HOST , user = DB_USER , passwd = DB_PASS , db = DB_NAME )
			num = cur.execute( "SELECT reason FROM banlist WHERE address = %s" , addr )
		if num > 0:
			( reason ) = cur.fetchone()
		cur.close()
		return reason
	
	def logEvent( self , type , event , login = "" , nick = "" , ip = "" ):
		try: 
			cur = self.db.cursor()
			cur.execute( "INSERT INTO log ( type , login , nick , ip , entry , date ) VALUES ( %s , %s , %s , %s , %s , NOW() )" , ( type , login , nick , ip , event ) )
			cur.close()
		except:
			print("mysql connection lost. check that mysql is up. reconnecting now.")
			cur = self.db.cursor()
			self.db = MySQLdb.connect( host = DB_HOST , user = DB_USER , passwd = DB_PASS , db = DB_NAME )
			cur.execute( "INSERT INTO log ( type , login , nick , ip , entry , date ) VALUES ( %s , %s , %s , %s , %s , NOW() )" , ( type , login , nick , ip , event ) )
			cur.close()
