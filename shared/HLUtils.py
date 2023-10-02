from __future__ import absolute_import
import sys,os


def shell_exec ( user, cmd, arg ):
	 os.environ['_LOGIN'] = user.account.login
	 os.environ['_UID'] = str(user.uid)
	 os.environ['_IP'] = user.ip
	 os.environ['_ICON'] = str(user.icon)
	 os.environ['_COLOR'] = str(user.status)
	 os.environ['_NICK'] = user.nick
	 os.environ['_NAME'] = user.account.name
	 os.environ['_PRIVS'] = str(user.account.privs)
	 os.environ['_FROOT'] = user.account.fileRoot
	 if user.isIRC: proto = "IRC"
	 else: proto = "Hotline"
	 os.environ['_PROTO'] = proto

	 path = cmd+" "+arg
	 path = path.replace('..', '')
	 path = "./support/exec/" + path
	 put, get, error = os.popen3(path)
	 
	 if( len(error.readlines()) == 1):
		return None
	 ret = ''
	 for result in get.readlines():
	       	 ret += result
	 return ret

#from twisted.internet import utils

#def shell_exec ( user, cmd, arg ):
#	return utils.getProcessOuput(cmd, arg)
