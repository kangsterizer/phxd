import os
import subprocess

def shell_exec(user, cmd, arg):
    os.environ['_LOGIN'] = user.account.login
    os.environ['_UID'] = str(user.uid)
    os.environ['_IP'] = user.ip
    os.environ['_ICON'] = str(user.icon)
    os.environ['_COLOR'] = str(user.status)
    # HACK -- Forcing user.nick to string manually here, it comes in as bytes
    os.environ['_NICK'] = user.nick.decode('mac-roman')
    os.environ['_NAME'] = user.account.name
    os.environ['_PRIVS'] = str(user.account.privs)
    os.environ['_FROOT'] = user.account.fileRoot
    proto = "IRC" if user.isIRC else "Hotline"
    os.environ['_PROTO'] = proto

    path = cmd + " " + arg
    path = path.replace('..', '')
    path = "./support/exec/" + path

    with subprocess.Popen(path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) as proc:
        ret = proc.stdout.read().decode()
        err = proc.stderr.read().decode()

    if err:
        return None
    return ret

#from twisted.internet import utils

#def shell_exec ( user, cmd, arg ):
#   return utils.getProcessOuput(cmd, arg)
