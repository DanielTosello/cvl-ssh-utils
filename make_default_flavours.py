import re
import siteConfig
import sys
import collections


class sshKeyDistDisplayStringsNCI(siteConfig.sshKeyDistDisplayStrings):
    def __init__(self):
        super(sshKeyDistDisplayStringsNCI, self).__init__()
        self.passwdPrompt="""Please enter the password for your NCI account."""
        self.passwdPromptIncorrect="Sorry, that password was incorrect.\n"+self.passwdPrompt
        self.passphrasePrompt="Please enter the passphrase for your SSH key"
        self.passphrasePromptIncorrect="""Sorry, that passphrase was incorrect.
Please enter the passphrase for you SSH Key
If you have forgoten the passphrase for you key, you may need to delete it and create a new key.
You can find this option under the Identity menu.
"""
        self.newPassphrase="""It looks like this is the first time you're using Strudel on this
computer. To use ssh key authentication, Strudel will generate a local
passphrase protected key on your computer which is used to
authenticate you to the NCI computers.

Please enter a new passphrase (twice to avoid typos) to protect your local key. 
After you've done this, your passphrase will be the primary method of
authentication for the launcher."""
        self.newPassphraseEmptyForbidden="Sorry, empty passphrases are forbidden.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseEmptyForbidden="Sorry, empty passphrases are forbidden."
        self.newPassphraseTooShort="Sorry, the passphrase must be at least six characters.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseTooShort="Passphrase is too short."
        self.newPassphraseMismatch="Sorry, the two passphrases you entered don't match.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseMismatch="Passphrases don't match!"
        self.newPassphraseTitle="Please enter a new passphrase"
        self.persistentMessage="Would you like to leave your current session running so that you can reconnect later?"
        self.reconnectMessage="An Existing Desktop was found. Would you like to reconnect or kill it and start a new desktop?"


class sshKeyDistDisplayStringsCVL(siteConfig.sshKeyDistDisplayStrings):
    def __init__(self):
        super(sshKeyDistDisplayStringsCVL, self).__init__()
        self.passwdPrompt="""Please enter the password for your CVL account.
This is the password you entered when you requested an account
at the website https://web.cvl.massive.org.au/users"""
        self.passwdPromptIncorrect="Sorry, that password was incorrect.\n"+self.passwdPrompt
        self.passphrasePrompt="Please enter the passphrase for your SSH key"
        self.passphrasePromptIncorrect="""Sorry, that passphrase was incorrect.
Please enter the passphrase for you SSH Key
If you have forgoten the passphrase for you key, you may need to delete it and create a new key.
You can find this option under the Identity menu.
"""
        self.newPassphrase="""It looks like this is the first time you're using the CVL on this
computer. To use the CVL, the launcher will generate a local
passphrase protected key on your computer which is used to
authenticate you and set up your remote CVL environment.

Please enter a new passphrase (twice to avoid typos) to protect your local key. 
After you've done this, your passphrase will be the primary method of
authentication for the launcher.

WHY?

This new method of authentication allows you to create file system
mounts to remote computer systems, and in the future it will support
launching remote HPC jobs."""
        self.newPassphraseEmptyForbidden="Sorry, empty passphrases are forbidden.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseEmptyForbidden="Sorry, empty passphrases are forbidden."
        self.newPassphraseTooShort="Sorry, the passphrase must be at least six characters.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseTooShort="Passphrase is too short."
        self.newPassphraseMismatch="Sorry, the two passphrases you entered don't match.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseMismatch="Passphrases don't match!"
        self.newPassphraseTitle="Please enter a new passphrase"
        self.persistentMessage="Would you like to leave your current session running so that you can reconnect later?"
        self.reconnectMessage="An Existing Desktop was found. Would you like to reconnect or kill it and start a new desktop?"

class sshKeyDistDisplayStringsMASSIVE(siteConfig.sshKeyDistDisplayStrings):
    def __init__(self):
        super(sshKeyDistDisplayStringsMASSIVE, self).__init__()
        self.passwdPrompt="""Please enter the password for your MASSIVE account."""
        self.passwdPromptIncorrect="Sorry, that password was incorrect.\n"+self.passwdPrompt
        self.passphrasePrompt="Please enter the passphrase for your SSH key"
        self.passphrasePromptIncorrect="""
Sorry, that passphrase was incorrect.
Please enter the passphrase for you SSH Key
If you have forgoten the passphrase for you key, you may need to delete it and create a new key.
You can find this option under the Identity menu.
"""
        self.newPassphrase="""It looks like this is the first time you're logging in to MASSIVE with this version of the launcher.
To make logging in faster and more secure, the launcher will generate a local
passphrase protected key on your computer which is used to
authenticate you and set up your MASSIVE desktop.

Please enter a new passphrase (twice to avoid typos) to protect your local key. 
After you've done this, your passphrase will be the primary method of
authentication for the launcher."""

        self.newPassphraseEmptyForbidden="Sorry, empty passphrases are forbidden.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseEmptyForbidden="Sorry, empty passphrases are forbidden."
        self.newPassphraseTooShort="Sorry, the passphrase must be at least 6 characters.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseTooShort="Passphrase is too short."
        self.newPassphraseMismatch="Sorry, the two passphrases you entered don't match.\n"+self.newPassphrase
        self.createNewKeyDialogNewPassphraseMismatch="Passphrases don't match!"
        self.newPassphraseTitle="Please enter a new passphrase"

def getMassiveSiteConfig(loginHost):
    massivevisible={}
    massivevisible['usernamePanel']=True
    massivevisible['projectPanel']=True
    massivevisible['loginHostPanel']=False
    massivevisible['resourcePanel']=True
    massivevisible['resolutionPanel']='Advanced'
    massivevisible['cipherPanel']='Advanced'
    massivevisible['debugCheckBoxPanel']='Advanced'
    massivevisible['advancedCheckBoxPanel']=True
    massivevisible['optionsDialog']=False
    massivevisible['ppnLabel']=False
    massivevisible['jobParams_ppn']=False
    massivevisible['ssh_key_mode_panel']='Advanced'
    massivevisible['copyid_mode_panel']=False
    c = siteConfig.siteConfig()
    c.visibility=massivevisible
    displayStrings=sshKeyDistDisplayStringsMASSIVE()
    c.displayStrings.__dict__.update(displayStrings.__dict__)
    c.messageRegexs=[re.compile("^INFO:(?P<info>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^WARN:(?P<warn>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^ERROR:(?P<error>.*(?:\n|\r\n?))",re.MULTILINE)]
    c.loginHost=loginHost
    cmd = '\"module load xmlstarlet ; qstat -x | xml sel -t -m \\"/Data/Job[starts-with(Job_Owner/text(),\'{username}@\') and starts-with(Job_Name/text(),\'desktop\') and job_state/text()!=\'C\']\\" -v \\" concat(./Job_Id/text(),\' \',./Walltime/Remaining/text())  \\" -n -\"'
    regex='(?P<jobid>(?P<jobidNumber>[0-9]+).\S+) (?P<remainingWalltime>.*)$'
    c.listAll=siteConfig.cmdRegEx(cmd,regex,requireMatch=False)
    cmd='\"module load pbs ; module load maui ; qstat -f {jobidNumber} -x\"'
    regex='.*<job_state>R</job_state>.*'
    c.running = siteConfig.cmdRegEx(cmd,regex)
    c.stop=siteConfig.cmdRegEx('\'qdel -a {jobidNumber}\'')
    c.stopForRestart=siteConfig.cmdRegEx('qdel {jobidNumber} ; sleep 5\'')
    cmd='\"module load xmlstarlet ; qstat -x -f {jobid} | xml sel -t -m \\"/Data/Job/exec_host/text()\\" -c \\".\\" -n - | cut -f 1 -d \\"/\\"\"'
    regex='(?P<execHost>\S+)'
    c.execHost=siteConfig.cmdRegEx(cmd,regex)
    c.startServer=siteConfig.cmdRegEx("\'/usr/local/desktop/request_visnode.sh {project} {hours} {nodes} True False False {resolution}\'","^(?P<jobid>(?P<jobidNumber>[0-9]+)\.\S+)\s*$")
    c.runSanityCheck=siteConfig.cmdRegEx("\'/usr/local/desktop/sanity_check.sh {launcher_version_number}\'")
    c.getProjects=siteConfig.cmdRegEx('\"glsproject -A -q | grep \',{username},\|\s{username},\|,{username}\s\|\s{username}\s\' \"','^(?P<group>\S+)\s+.*$')
    c.showStart=siteConfig.cmdRegEx("showstart {jobid}","Estimated Rsv based start .*?on (?P<estimatedStart>.*)")
    c.vncDisplay= siteConfig.cmdRegEx('"/usr/bin/ssh {execHost} \' module load turbovnc ; vncserver -list\'"','^(?P<vncDisplay>:[0-9]+)\s*(?P<vncPID>[0-9]+)\s*$')
    c.otp= siteConfig.cmdRegEx('"/usr/bin/ssh {execHost} \' module load turbovnc ; vncpasswd -o -display localhost{vncDisplay}\'"','^\s*Full control one-time password: (?P<vncPasswd>[0-9]+)\s*$')
    c.agent=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=yes -l {username} {loginHost} \"/usr/bin/ssh -A {execHost} \\"echo agent_hello; bash \\"\"','agent_hello',async=True)
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=yes -L {localPortNumber}:{execHost}:{remotePortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)

    cmd='"echo DBUS_SESSION_BUS_ADDRESS=dummy_dbus_session_bus_address"'
    regex='^DBUS_SESSION_BUS_ADDRESS=(?P<dbusSessionBusAddress>.*)$'
    c.dbusSessionBusAddress=siteConfig.cmdRegEx(cmd,regex)

    cmd='\"/usr/local/desktop/get_ephemeral_port.py\"'
    regex='^(?P<intermediateWebDavPortNumber>[0-9]+)$'
    c.webDavIntermediatePort=siteConfig.cmdRegEx(cmd,regex)

    cmd='\"/usr/bin/ssh {execHost} /usr/local/desktop/get_ephemeral_port.py\"'
    regex='^(?P<remoteWebDavPortNumber>[0-9]+)$'
    c.webDavRemotePort=siteConfig.cmdRegEx(cmd,regex)

    cmd='echo Mounting WebDAV...' # For CentOS 5 / KDE, we are not really "mounting", just displaying the WebDAV share in Konqueror.
    c.webDavMount=siteConfig.cmdRegEx(cmd)

    cmd='"/usr/bin/ssh {execHost} \'DISPLAY={vncDisplay} /usr/bin/konqueror webdav://{localUsername}:{vncPasswd}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\'"'
    c.openWebDavShareInRemoteFileBrowser=siteConfig.cmdRegEx(cmd)

    # The Window ID is not needed for MASSIVE.  We use the server-side script: /usr/local/desktop/close_webdav_window.sh which figures out which window to close.
    cmd='"echo DummyWebDavWindowID=-1"'
    regex='^DummyWebDavWindowID=(?P<webDavWindowID>.*)$'
    c.webDavWindowID=siteConfig.cmdRegEx(cmd,regex)

    cmd='"/usr/bin/ssh {execHost} \'echo -e \\"You can access your local home directory in Konqueror with the URL:%sbr%s\\nwebdav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}%sbr%s\\nYour one-time password is {vncPasswd}\\" > ~/.vnc/\\$(hostname){vncDisplay}-webdav.txt;\'"'
    c.displayWebDavInfoDialogOnRemoteDesktop = siteConfig.cmdRegEx(cmd)

    # Chris trying to avoid using the intermediate port:
    #cmd='{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -oExitOnForwardFailure=yes -R {execHost}:{remoteWebDavPortNumber}:localhost:{localWebDavPortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"'

    cmd='{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -oExitOnForwardFailure=yes -R {intermediateWebDavPortNumber}:localhost:{localWebDavPortNumber} -l {username} {loginHost} "ssh -R {remoteWebDavPortNumber}:localhost:{intermediateWebDavPortNumber} {execHost} \'echo tunnel_hello; bash\'"'
    regex='tunnel_hello'
    c.webDavTunnel=siteConfig.cmdRegEx(cmd,regex,async=True)

    cmd = 'echo hello'
    regex = 'hello'
    c.webDavUnmount=siteConfig.cmdRegEx(cmd,regex)

    cmd = '"/usr/bin/ssh {execHost} \'DISPLAY={vncDisplay} /usr/local/desktop/close_webdav_window.sh webdav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\'"'
    c.webDavCloseWindow=siteConfig.cmdRegEx(cmd)

    return c

def getCQUGPUConfig(queue):
    c = getCVLSiteConfig(queue)
    s = sshKeyDistDisplayStringsNCI()
    c.displayStrings.__dict__.update(s.__dict__)
    c.visibility['resourcePanel']=False
    c.visibility['ppnLabel']=False
    c.visibility['jobParams_ppn']=False
    c.loginHost='isaac.cqu.edu.au'
    c.directConnect=False
    cmd='\"qstat -f {jobidNumber} \"'
    regex='.*job_state = R.*'
    c.running=siteConfig.cmdRegEx(cmd,regex)
    c.stop=siteConfig.cmdRegEx('\" qdel {jobidNumber}\"')
    c.stopForRestart=siteConfig.cmdRegEx('\"qdel {jobidNumber}\"')
    c.agent=siteConfig.cmdRegEx()
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:{execHost}:{remotePortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)
    c.otp= siteConfig.cmdRegEx('\'cat ~/.vnc/clearpass\'','^(?P<vncPasswd>\S+)$')
    #cmd='\" mkdir ~/.vnc ; rm -f ~/.vnc/passwdfile ; touch ~/.vnc/passwdfile ; chmod 600 ~/.vnc/passwdfile ; passwd=\"\'$\'\"( dd if=/dev/urandom bs=1 count=8 2>/dev/null | md5sum | cut -b 1-8 ) ; echo \"\'$\'\"passwd > ~/.vnc/passwdfile ;  echo \\\" vncserver -geometry {resolution} ; sleep 10000000000\\\" | qsub  -l ncpus=1,mem=4g,ngpus=1 -N INTERACT  -o .vnc/ -e .vnc/ \"'

    cmd='\" /usr/local/bin/vnc-checker.sh ; rm -f ~/.vnc/clearpass ; touch ~/.vnc/clearpass ; chmod 600 ~/.vnc/clearpass ; passwd=\"\'$\'\"( dd if=/dev/urandom bs=1 count=8 2>/dev/null | md5sum | cut -b 1-8 ) ; echo \"\'$\'\"passwd > ~/.vnc/clearpass ; cat ~/.vnc/clearpass | vncpasswd -f > ~/.vnc/passwd ; chmod 600 ~/.vnc/passwd ;  echo \\\" vncserver -geometry {resolution} ; sleep 10000000000\\\" | qsub  -l ncpus=1,mem=4g,ngpus=1 -N INTERACT  -o .vnc/ -e .vnc/ \"'
    regex="^(?P<jobid>(?P<jobidNumber>[0-9]+)\.\S+)\s*$"
    c.startServer=siteConfig.cmdRegEx(cmd,regex)
    c.vncDisplay=siteConfig.cmdRegEx('\'cat ~/.vnc/{execHost}*.log\'','port 59(?P<vncDisplay>[0-9]+)')
    cmd='\" qstat -f {jobidNumber} | grep exec_host\"'
    regex='^\s*exec_host = (?P<execHost>[a-z]+[0-9]+)\[.*$'
    c.execHost = siteConfig.cmdRegEx(cmd,regex)
    c.listAll=siteConfig.cmdRegEx('\"qstat -u {username} | tail -n +6\"','^\s*(?P<jobid>(?P<jobidNumber>[0-9]+).\S+)\s+\S+\s+\S+\s+(?P<jobname>INTERACT)\s+(?P<sessionID>\S+)\s+(?P<nodes>\S+)\s+(?P<tasks>\S+)\s+(?P<mem>\S+)\s+(?P<reqTime>\S+)\s+(?P<state>[^C])\s+(?P<elapTime>\S+)\s*$',requireMatch=False)
    return c

def getRaijinSiteConfig(queue):
    c = getCVLSiteConfig(queue)
    s = sshKeyDistDisplayStringsNCI()
    c.displayStrings.__dict__.update(s.__dict__)
    c.visibility['resourcePanel']=True
    c.visibility['ppnLabel']=False
    c.visibility['jobParams_ppn']=False
    c.visibility['ssh_key_mode_panel']='Advanced'
    c.visibility['copyid_mode_panel']=False
    c.loginHost='raijin.nci.org.au'
    c.directConnect=False
    cmd='\"module load pbs ; qstat -f {jobidNumber} \"'
    regex='.*job_state = R.*'
    c.running=siteConfig.cmdRegEx(cmd,regex)
    c.stop=siteConfig.cmdRegEx('\"module load pbs ; qdel {jobidNumber}\"')
    c.stopForRestart=siteConfig.cmdRegEx('\"module load pbs ; qdel {jobidNumber}\"')
    c.agent=siteConfig.cmdRegEx()
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:{execHost}:{remotePortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)
    c.otp= siteConfig.cmdRegEx('\'cat ~/.vnc/passwdfile\'','^(?P<vncPasswd>\S+)$')
    cmd='\" mkdir ~/.vnc ; rm -f ~/.vnc/passwdfile ; touch ~/.vnc/passwdfile ; chmod 600 ~/.vnc/passwdfile ; passwd=\"\'$\'\"( dd if=/dev/urandom bs=1 count=8 2>/dev/null | md5sum | cut -b 1-8 ) ; echo \"\'$\'\"passwd > ~/.vnc/passwdfile ;  echo \\\" module load x11vnc ; x11vnc -usepw -create -shared -forever\\\" | qsub -q %s -l ncpus={nodes} -N desktop_{username} -l walltime={hours}:00 -o .vnc/ -e .vnc/ \"'%queue
    regex="^(?P<jobid>(?P<jobidNumber>[0-9]+)\.\S+)\s*$"
    c.startServer=siteConfig.cmdRegEx(cmd,regex)
    c.vncDisplay=siteConfig.cmdRegEx('\'qcat {jobidNumber}\'','PORT=59(?P<vncDisplay>[0-9]+)')
    cmd='\"module load pbs ; qstat -f {jobidNumber} | grep exec_host\"'
    regex='^\s*exec_host = (?P<execHost>r[0-9]+)\/.*$'
    c.execHost = siteConfig.cmdRegEx(cmd,regex)
    c.listAll=siteConfig.cmdRegEx('\"module load pbs ; qstat -u {username} | tail -n +6\"','^\s*(?P<jobid>(?P<jobidNumber>[0-9]+).\S+)\s+\S+\s+\S+\s+(?P<jobname>desktop_\S+)\s+(?P<sessionID>\S+)\s+(?P<nodes>\S+)\s+(?P<tasks>\S+)\s+(?P<mem>\S+)\s+(?P<reqTime>\S+)\s+(?P<state>[^C])\s+(?P<elapTime>\S+)\s*$',requireMatch=False)
    return c

def getRaijinLoginSiteConfig(loginnode):
    c = getCVLSiteConfig(" ")
    c.visibility['resourcePanel']=False
    c.visibility['ssh_key_mode_panel']='Advanced'
    c.visibility['copyid_mode_panel']=False
    c.loginHost=loginnode
    c.directConnect=False
    cmd='\" pid=\"\'$\'\"( cat ~/.vnc/{loginHost}.log | grep pid | rev | cut -f 1 -d \\\" \\\" | rev ) ; ps -p \"\'$\'\"pid -o pid,pgrp,user --no-headers 2>/dev/null\"'
    regex='(?P<pid>[0-9]+)\s+(?P<pgrp>[0-9]+)\s+{username}'
    c.running=siteConfig.cmdRegEx(cmd,regex)
    # For reasons I don't understand Xvfb does not inherit the process group of x11vnc
    c.stop=siteConfig.cmdRegEx('\"kill -- -{pgrp} ; pkill -U {username} Xvfb\"')
    c.stopForRestart=siteConfig.cmdRegEx('\"kill -- -{pgrp} ; pkill -U {username} Xvfb\"')
    c.agent=siteConfig.cmdRegEx()
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:localhost:{remotePortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)
    c.otp= siteConfig.cmdRegEx('\'cat ~/.vnc/passwdfile\'','^(?P<vncPasswd>\S+)$')
    cmd='\" mkdir ~/.vnc 2>/dev/null ; rm -f ~/.vnc/{loginHost}.log ; rm -f ~/.vnc/passwdfile ; touch ~/.vnc/passwdfile ; chmod 600 ~/.vnc/passwdfile ; passwd=\"\'$\'\"( dd if=/dev/urandom bs=1 count=8 2>/dev/null | md5sum | cut -b 1-8 ) ; echo \"\'$\'\"passwd > ~/.vnc/passwdfile ; module load x11vnc ; x11vnc -usepw -create -shared -forever > .vnc/{loginHost}.log 2>{ampersand}1 {ampersand} echo started\"'
    c.startServer=siteConfig.cmdRegEx(cmd,"started")
    c.vncDisplay=siteConfig.cmdRegEx('\'cat ~/.vnc/{loginHost}.log\'','PORT=59(?P<vncDisplay>[0-9]+)')
    c.execHost = siteConfig.cmdRegEx()
    c.listAll=siteConfig.cmdRegEx('\"pid=\"\'$\'\"( cat ~/.vnc/{loginHost}.log 2>/dev/null | grep pid | rev | cut -f 1 -d \\\" \\\" | rev ) ; ps -p \"\'$\'\"pid -o pid,pgrp,user --no-headers 2>/dev/null\"','(?P<pid>[0-9]+)\s+(?P<pgrp>[0-9]+)\s+{username}',requireMatch=False)
    return c

def getCVLSiteConfigXML(queue):
    cvlvisible={}
    cvlvisible['loginHostPanel']=False
    cvlvisible['usernamePanel']=True
    cvlvisible['projectPanel']=False
    cvlvisible['resourcePanel']='Advanced'
    cvlvisible['ppnLabel']=False
    cvlvisible['jobParams_ppn']=False
    cvlvisible['resolutionPanel']='Advanced'
    cvlvisible['cipherPanel']='Advanced'
    cvlvisible['debugCheckBoxPanel']='Advanced'
    cvlvisible['advancedCheckBoxPanel']=True
    cvlvisible['optionsDialog']=False
    cvlvisible['ppnLabel']=False
    cvlvisible['jobParams_ppn']=False
    cvlvisible['ssh_key_mode_panel']='Advanced'
    cvlvisible['copyid_mode_panel']='Advanced'
    c = siteConfig.siteConfig()
    cvlstrings = sshKeyDistDisplayStringsCVL()
    c.displayStrings.__dict__.update(cvlstrings.__dict__)
    c.visibility=cvlvisible
    c.loginHost='login.cvl.massive.org.au'
    c.directConnect=True


    cmd = '\"module load pbs ; qstat -x | xmlstarlet sel -t -m \\"/Data/Job[starts-with(Job_Owner/text(),\'{username}@\') and starts-with(Job_Name/text(),\'desktop\') and job_state/text()!=\'C\']\\" -v \\" concat(./Job_Id/text(),\' \',./Walltime/Remaining/text())  \\" -n -\"'
    regex='(?P<jobid>(?P<jobidNumber>[0-9]+).\S+) (?P<remainingWalltime>.*)$'
    c.listAll=siteConfig.cmdRegEx(cmd,regex,requireMatch=False)


    c.messageRegexs=[re.compile("^INFO:(?P<info>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^WARN:(?P<warn>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^ERROR:(?P<error>.*(?:\n|\r\n?))",re.MULTILINE)]
    cmd='\"module load pbs ; qstat -f {jobidNumber} | grep exec_host | sed \'s/\ \ */\ /g\' | cut -f 4 -d \' \' | cut -f 1 -d \'/\' | xargs -iname hostn name | grep address | sed \'s/\ \ */\ /g\' | cut -f 3 -d \' \' | xargs -iip echo execHost ip; qstat -f {jobidNumber}\"'
    regex='^\s*execHost (?P<execHost>\S+)\s*$'
    c.execHost = siteConfig.cmdRegEx(cmd,regex)
    cmd='\"groups | sed \'s@ @\\n@g\'\"' # '\'groups | sed \'s\/\\\\ \/\\\\\\\\n\/g\'\''
    regex='^\s*(?P<group>\S+)\s*$'
    c.getProjects = siteConfig.cmdRegEx(cmd,regex)
    cmd='\"module load pbs ; module load maui ; qstat -f {jobidNumber} -x\"'
    regex='.*<job_state>R</job_state>.*'
    c.running=siteConfig.cmdRegEx(cmd,regex)
    cmd="\"module load pbs ; module load maui ; echo \'module load pbs ; /usr/local/bin/vncsession --vnc turbovnc --geometry {resolution} ; sleep 36000000 \' |  qsub -q %s -l nodes=1:ppn=1 -l walltime={hours}:00:00 -N desktop_{username} -o .vnc/ -e .vnc/ \""%queue
    regex="^(?P<jobid>(?P<jobidNumber>[0-9]+)\.\S+)\s*$"
    c.startServer=siteConfig.cmdRegEx(cmd,regex)
    c.stop=siteConfig.cmdRegEx('\"module load pbs ; module load maui ; qdel -a {jobidNumber}\"')
    c.stopForRestart=siteConfig.cmdRegEx('\"module load pbs ; module load maui ; qdel {jobidNumber}\"')
    c.vncDisplay= siteConfig.cmdRegEx('\"cat /var/spool/torque/spool/{jobidNumber}.*\"' ,'^.*?started on display \S+(?P<vncDisplay>:[0-9]+)\s*$',host='exec')
    cmd= '\"module load turbovnc ; vncpasswd -o -display localhost{vncDisplay}\"'
    regex='^\s*Full control one-time password: (?P<vncPasswd>[0-9]+)\s*$'
    c.otp=siteConfig.cmdRegEx(cmd,regex,host='exec')
    c.agent=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -l {username} {execHost} "echo agent_hello; bash "','agent_hello',async=True)
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:localhost:{remotePortNumber} -l {username} {execHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)

    cmd='"/usr/bin/ssh {execHost} \'export DISPLAY={vncDisplay};timeout 15 /usr/local/bin/cat_dbus_session_file.sh\'"'
    regex='^DBUS_SESSION_BUS_ADDRESS=(?P<dbusSessionBusAddress>.*)$'
    c.dbusSessionBusAddress=siteConfig.cmdRegEx(cmd,regex)

    cmd='\"/usr/local/bin/get_ephemeral_port.py\"'
    regex='^(?P<intermediateWebDavPortNumber>[0-9]+)$'
    c.webDavIntermediatePort=siteConfig.cmdRegEx(cmd,regex,host='exec')

    cmd='\"/usr/local/bin/get_ephemeral_port.py\"'
    regex='^(?P<remoteWebDavPortNumber>[0-9]+)$'
    c.webDavRemotePort=siteConfig.cmdRegEx(cmd,regex,host='exec')

    # Below, I initially tried to respect the user's Nautilus setting of always_use_location_entry and change it back after launching Nautilus,
    # but doing so changes this setting in already-running Nautilus windows, and I want the user to see Nautilus's location bar when showing 
    # them the WebDav share.  So now, I just brutally change the user's Nautilus location-bar setting to always_use_location_entry.
    # Note that we might end up mounting WebDAV in a completely different way (e.g. using wdfs), but for now I'm trying to make the user
    # experience similar on MASSIVE and the CVL.  On MASSIVE, users are not automatically added to the "fuse" group, but they can still 
    # access a WebDAV share within Konqueror.  The method below for the CVL/Nautilus does require fuse membership, but it ends up looking
    # similar to MASSIVE/Konqueror from the user's point of view.  

    cmd="\"/usr/bin/ssh {execHost} \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};echo \\\\\\\"import pexpect;child = pexpect.spawn('gvfs-mount dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}');child.expect('Password: ');child.sendline('{vncPasswd}');child.expect(pexpect.EOF);child.close();print 'gvfs-mount returned ' + str(child.exitstatus)\\\\\\\" {pipe} python\\\"\""
    regex='^gvfs-mount returned (?P<webDavMountingExitCode>.*)$'
    c.webDavMount=siteConfig.cmdRegEx(cmd,regex)

    cmd="\"/usr/bin/ssh {execHost} \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};/usr/bin/gconftool-2 --type=Boolean --set /apps/nautilus/preferences/always_use_location_entry true {ampersand}{ampersand} DISPLAY={vncDisplay} xdg-open dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\\\"\"" 
    c.openWebDavShareInRemoteFileBrowser=siteConfig.cmdRegEx(cmd)

    cmd='"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress}; DISPLAY={vncDisplay} xwininfo -root -tree\'"'
    regex= '^\s+(?P<webDavWindowID>\S+)\s+"{homeDirectoryWebDavShareName}.*Browser.*$'
    c.webDavWindowID=siteConfig.cmdRegEx(cmd,regex)

    cmd = '"/usr/bin/ssh {execHost} \'echo -e \\"You can access your local home directory in Nautilus File Browser, using the location:\\n\\ndav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\\n\\nYour one-time password is {vncPasswd}\\" > ~/.vnc/\\$(hostname){vncDisplay}-webdav.txt\'"'
    c.displayWebDavInfoDialogOnRemoteDesktop=siteConfig.cmdRegEx(cmd)

    cmd='{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -oExitOnForwardFailure=yes -R {remoteWebDavPortNumber}:localhost:{localWebDavPortNumber} -l {username} {execHost} "echo tunnel_hello; bash"'
    regex='tunnel_hello'
    c.webDavTunnel=siteConfig.cmdRegEx(cmd,regex,async=True)

    # 1. I'm using gvfs-mount --unmount-scheme dav for now, to unmount all GVFS WebDAV mounts,
    #    because using "gvfs-mount --unmount " on a specific mount point from a Launcher
    #    subprocess doesn't seem to work reliably, even though it works fine outside of the 
    #    Launcher.
    # 2. I'm using timeout with gvfs-mount, because sometimes the process never exits
    #    when unmounting, even though the unmounting operation is complete.
    #cmd = '"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};DISPLAY={vncDisplay} timeout 3 gvfs-mount -u \".gvfs/WebDAV on localhost\"\'"'
    cmd = '"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay};timeout 1 gvfs-mount --unmount-scheme dav\'"'
    c.webDavUnmount=siteConfig.cmdRegEx(cmd)

    cmd = '"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay}; wmctrl -F -i -c {webDavWindowID}\'"'
    c.webDavCloseWindow=siteConfig.cmdRegEx(cmd)
    cmd = '"/usr/bin/ssh {execHost} \'module load keyutility ; mountUtility.py\'"'
    c.onConnectScript = siteConfig.cmdRegEx(cmd)
    return c

def getCVLSiteConfig(queue):
    cvlvisible={}
    cvlvisible['loginHostPanel']=False
    cvlvisible['usernamePanel']=True
    cvlvisible['projectPanel']=False
    cvlvisible['resourcePanel']='Advanced'
    cvlvisible['ppnLabel']=False
    cvlvisible['jobParams_ppn']=False
    cvlvisible['resolutionPanel']='Advanced'
    cvlvisible['cipherPanel']='Advanced'
    cvlvisible['debugCheckBoxPanel']='Advanced'
    cvlvisible['advancedCheckBoxPanel']=True
    cvlvisible['optionsDialog']=False
    cvlvisible['ppnLabel']=False
    cvlvisible['jobParams_ppn']=False
    c = siteConfig.siteConfig()
    cvlstrings = sshKeyDistDisplayStringsCVL()
    c.displayStrings.__dict__.update(cvlstrings.__dict__)
    c.visibility=cvlvisible
    c.loginHost='login.cvl.massive.org.au'
    c.directConnect=True
    c.messageRegexs=[re.compile("^INFO:(?P<info>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^WARN:(?P<warn>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^ERROR:(?P<error>.*(?:\n|\r\n?))",re.MULTILINE)]
    cmd='\"module load pbs ; qstat -f {jobidNumber} | grep exec_host | sed \'s/\ \ */\ /g\' | cut -f 4 -d \' \' | cut -f 1 -d \'/\' | xargs -iname hostn name | grep address | sed \'s/\ \ */\ /g\' | cut -f 3 -d \' \' | xargs -iip echo execHost ip; qstat -f {jobidNumber}\"'
    regex='^\s*execHost (?P<execHost>\S+)\s*$'
    c.execHost = siteConfig.cmdRegEx(cmd,regex)
    cmd='\"groups | sed \'s@ @\\n@g\'\"' # '\'groups | sed \'s\/\\\\ \/\\\\\\\\n\/g\'\''
    regex='^\s*(?P<group>\S+)\s*$'
    c.getProjects = siteConfig.cmdRegEx(cmd,regex)
    c.listAll=siteConfig.cmdRegEx('\"module load pbs ; qstat -u {username} | tail -n +6\"','^\s*(?P<jobid>(?P<jobidNumber>[0-9]+).\S+)\s+\S+\s+(?P<queue>%s)\s+(?P<jobname>desktop_\S+)\s+(?P<sessionID>\S+)\s+(?P<nodes>\S+)\s+(?P<tasks>\S+)\s+(?P<mem>\S+)\s+(?P<reqTime>\S+)\s+(?P<state>[^C])\s+(?P<elapTime>\S+)\s*$'%queue,requireMatch=False)
    cmd='\"module load pbs ; module load maui ; qstat -f {jobidNumber} -x\"'
    regex='.*<job_state>R</job_state>.*'
    c.running=siteConfig.cmdRegEx(cmd,regex)
    cmd="\"module load pbs ; module load maui ; echo \'module load pbs ; /usr/local/bin/vncsession --vnc turbovnc --geometry {resolution} ; sleep 36000000 \' |  qsub -q %s -l nodes=1:ppn=1 -l walltime=48:00:00 -N desktop_{username} -o .vnc/ -e .vnc/ \""%queue
    regex="^(?P<jobid>(?P<jobidNumber>[0-9]+)\.\S+)\s*$"
    c.startServer=siteConfig.cmdRegEx(cmd,regex)
    c.stop=siteConfig.cmdRegEx('\"module load pbs ; module load maui ; qdel -a {jobidNumber}\"')
    c.stopForRestart=siteConfig.cmdRegEx('\"module load pbs ; module load maui ; qdel {jobidNumber}\"')
    c.vncDisplay= siteConfig.cmdRegEx('\"cat /var/spool/torque/spool/{jobidNumber}.*\"' ,'^.*?started on display \S+(?P<vncDisplay>:[0-9]+)\s*$',host='exec')
    cmd= '\"module load turbovnc ; vncpasswd -o -display localhost{vncDisplay}\"'
    regex='^\s*Full control one-time password: (?P<vncPasswd>[0-9]+)\s*$'
    c.otp=siteConfig.cmdRegEx(cmd,regex,host='exec')
    c.agent=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -l {username} {execHost} "echo agent_hello; bash "','agent_hello',async=True)
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:localhost:{remotePortNumber} -l {username} {execHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)

    cmd='"/usr/bin/ssh {execHost} \'export DISPLAY={vncDisplay};timeout 15 /usr/local/bin/cat_dbus_session_file.sh\'"'
    regex='^DBUS_SESSION_BUS_ADDRESS=(?P<dbusSessionBusAddress>.*)$'
    c.dbusSessionBusAddress=siteConfig.cmdRegEx(cmd,regex)

    cmd='\"/usr/local/bin/get_ephemeral_port.py\"'
    regex='^(?P<intermediateWebDavPortNumber>[0-9]+)$'
    c.webDavIntermediatePort=siteConfig.cmdRegEx(cmd,regex,host='exec')

    cmd='\"/usr/local/bin/get_ephemeral_port.py\"'
    regex='^(?P<remoteWebDavPortNumber>[0-9]+)$'
    c.webDavRemotePort=siteConfig.cmdRegEx(cmd,regex,host='exec')

    # Below, I initially tried to respect the user's Nautilus setting of always_use_location_entry and change it back after launching Nautilus,
    # but doing so changes this setting in already-running Nautilus windows, and I want the user to see Nautilus's location bar when showing 
    # them the WebDav share.  So now, I just brutally change the user's Nautilus location-bar setting to always_use_location_entry.
    # Note that we might end up mounting WebDAV in a completely different way (e.g. using wdfs), but for now I'm trying to make the user
    # experience similar on MASSIVE and the CVL.  On MASSIVE, users are not automatically added to the "fuse" group, but they can still 
    # access a WebDAV share within Konqueror.  The method below for the CVL/Nautilus does require fuse membership, but it ends up looking
    # similar to MASSIVE/Konqueror from the user's point of view.  

    cmd="\"/usr/bin/ssh {execHost} \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};echo \\\\\\\"import pexpect;child = pexpect.spawn('gvfs-mount dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}');child.expect('Password: ');child.sendline('{vncPasswd}');child.expect(pexpect.EOF);child.close();print 'gvfs-mount returned ' + str(child.exitstatus)\\\\\\\" {pipe} python\\\"\""
    regex='^gvfs-mount returned (?P<webDavMountingExitCode>.*)$'
    c.webDavMount=siteConfig.cmdRegEx(cmd,regex)

    cmd="\"/usr/bin/ssh {execHost} \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};/usr/bin/gconftool-2 --type=Boolean --set /apps/nautilus/preferences/always_use_location_entry true {ampersand}{ampersand} DISPLAY={vncDisplay} xdg-open dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\\\"\"" 
    c.openWebDavShareInRemoteFileBrowser=siteConfig.cmdRegEx(cmd)

    cmd='"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress}; DISPLAY={vncDisplay} xwininfo -root -tree\'"'
    regex= '^\s+(?P<webDavWindowID>\S+)\s+"{homeDirectoryWebDavShareName}.*Browser.*$'
    c.webDavWindowID=siteConfig.cmdRegEx(cmd,regex)

    cmd = '"/usr/bin/ssh {execHost} \'echo -e \\"You can access your local home directory in Nautilus File Browser, using the location:\\n\\ndav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\\n\\nYour one-time password is {vncPasswd}\\" > ~/.vnc/\\$(hostname){vncDisplay}-webdav.txt\'"'
    c.displayWebDavInfoDialogOnRemoteDesktop=siteConfig.cmdRegEx(cmd)

    cmd='{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -oExitOnForwardFailure=yes -R {remoteWebDavPortNumber}:localhost:{localWebDavPortNumber} -l {username} {execHost} "echo tunnel_hello; bash"'
    regex='tunnel_hello'
    c.webDavTunnel=siteConfig.cmdRegEx(cmd,regex,async=True)

    # 1. I'm using gvfs-mount --unmount-scheme dav for now, to unmount all GVFS WebDAV mounts,
    #    because using "gvfs-mount --unmount " on a specific mount point from a Launcher
    #    subprocess doesn't seem to work reliably, even though it works fine outside of the 
    #    Launcher.
    # 2. I'm using timeout with gvfs-mount, because sometimes the process never exits
    #    when unmounting, even though the unmounting operation is complete.
    #cmd = '"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};DISPLAY={vncDisplay} timeout 3 gvfs-mount -u \".gvfs/WebDAV on localhost\"\'"'
    cmd = '"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay};timeout 1 gvfs-mount --unmount-scheme dav\'"'
    c.webDavUnmount=siteConfig.cmdRegEx(cmd)

    cmd = '"/usr/bin/ssh {execHost} \'export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay}; wmctrl -F -i -c {webDavWindowID}\'"'
    c.webDavCloseWindow=siteConfig.cmdRegEx(cmd)
    cmd = '"/usr/bin/ssh {execHost} \'module load keyutility ; mountUtility.py\'"'
    c.onConnectScript = siteConfig.cmdRegEx(cmd)
    return c

def getOtherTurboVNCConfig(configName):
    Visible={}
    Visible['usernamePanel']=True
    Visible['projectPanel']=False
    Visible['loginHostPanel']=True
    Visible['resourcePanel']=False
    Visible['resolutionPanel']='Advanced'
    Visible['cipherPanel']='Advanced'
    Visible['debugCheckBoxPanel']='Advanced'
    Visible['advancedCheckBoxPanel']=True
    Visible['optionsDialog']=False
    c = siteConfig.siteConfig()
    c.visibility=Visible
    c.listAll=siteConfig.cmdRegEx('\'module load turbovnc ; vncserver -list\'','^(?P<vncDisplay>:[0-9]+)\s+[0-9]+\s*$',requireMatch=False)
    c.startServer=siteConfig.cmdRegEx('\"/usr/local/bin/vncsession --vnc turbovnc --geometry {resolution}\"','^.*?started on display \S+(?P<vncDisplay>:[0-9]+)\s*$')
    c.stop=siteConfig.cmdRegEx('\'module load turbovnc ; vncserver -kill {vncDisplay}\'')
    c.stopForRestart=siteConfig.cmdRegEx('\'module load turbovnc ; vncserver -kill {vncDisplay}\'')
    c.otp= siteConfig.cmdRegEx('\'module load turbovnc ; vncpasswd -o -display localhost{vncDisplay}\'','^\s*Full control one-time password: (?P<vncPasswd>[0-9]+)\s*$')
    c.agent=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -l {username} {loginHost} "echo agent_hello; bash "','agent_hello',async=True)
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:localhost:{remotePortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)

    cmd='"export DISPLAY={vncDisplay};timeout 15 /usr/local/bin/cat_dbus_session_file.sh"'
    regex='^DBUS_SESSION_BUS_ADDRESS=(?P<dbusSessionBusAddress>.*)$'
    c.dbusSessionBusAddress=siteConfig.cmdRegEx(cmd,regex)

    cmd='\"/usr/local/bin/get_ephemeral_port.py\"'
    regex='^(?P<remoteWebDavPortNumber>[0-9]+)$'
    c.webDavRemotePort=siteConfig.cmdRegEx(cmd,regex)

    cmd='{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -oExitOnForwardFailure=yes -R {remoteWebDavPortNumber}:localhost:{localWebDavPortNumber} -l {username} {loginHost} \'echo tunnel_hello; bash\''
    regex='tunnel_hello'
    c.webDavTunnel=siteConfig.cmdRegEx(cmd,regex,async=True)

    cmd="\"/usr/bin/ssh -oStrictHostKeyChecking=no localhost \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};echo \\\\\\\"import pexpect;child = pexpect.spawn('gvfs-mount dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}');child.expect('Password: ');child.sendline('{vncPasswd}');child.expect(pexpect.EOF);child.close();print 'gvfs-mount returned ' + str(child.exitstatus)\\\\\\\" {pipe} python\\\"\"" 
    regex='^gvfs-mount returned (?P<webDavMountingExitCode>.*)$'
    c.webDavMount=siteConfig.cmdRegEx(cmd,regex)

    cmd="\"/usr/bin/ssh -oStrictHostKeyChecking=no localhost \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};/usr/bin/gconftool-2 --type=Boolean --set /apps/nautilus/preferences/always_use_location_entry true {ampersand}{ampersand} DISPLAY={vncDisplay} xdg-open dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\\\"\"" 
    c.openWebDavShareInRemoteFileBrowser=siteConfig.cmdRegEx(cmd)

    cmd='"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress}; DISPLAY={vncDisplay} xwininfo -root -tree"'
    regex= '^\s+(?P<webDavWindowID>\S+)\s+"{homeDirectoryWebDavShareName}.*Browser.*$'
    c.webDavWindowID=siteConfig.cmdRegEx(cmd,regex)

    # 1. I'm using gvfs-mount --unmount-scheme dav for now, to unmount all GVFS WebDAV mounts,
    #    because using "gvfs-mount --unmount " on a specific mount point from a Launcher
    #    subprocess doesn't seem to work reliably, even though it works fine outside of the 
    #    Launcher.
    # 2. I'm using timeout with gvfs-mount, because sometimes the process never exits
    #    when unmounting, even though the unmounting operation is complete.
    cmd = '"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay};timeout 1 gvfs-mount --unmount-scheme dav"'
    c.webDavUnmount=siteConfig.cmdRegEx(cmd)

    cmd = '"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay}; wmctrl -F -i -c {webDavWindowID}"'
    c.webDavCloseWindow=siteConfig.cmdRegEx(cmd)
    return c

def getGenericVNCSession():
    import re
    Visible={}
    Visible['usernamePanel']=True
    Visible['projectPanel']=False
    Visible['loginHostPanel']=True
    Visible['resourcePanel']=False
    Visible['resolutionPanel']='Advanced'
    Visible['cipherPanel']='Advanced'
    Visible['debugCheckBoxPanel']='Advanced'
    Visible['advancedCheckBoxPanel']=True
    Visible['optionsDialog']=False
    c = siteConfig.siteConfig()
    c.visibility=Visible

    siteConfigDict={}
    c.messageRegexs=[re.compile("^INFO:(?P<info>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^WARN:(?P<warn>.*(?:\n|\r\n?))",re.MULTILINE),re.compile("^ERROR:(?P<error>.*(?:\n|\r\n?))",re.MULTILINE)]
    #c.listAll=siteConfig.cmdRegEx('\'vncserver -list\'','^(?P<vncDisplay>:[0-9]+)\s+[0-9]+\s*$',requireMatch=False)
    c.listAll=siteConfig.cmdRegEx('\'ls ~/.vnc/`hostname`*pid\'','^\S+(?P<vncDisplay>:[0-9]+).pid$',requireMatch=False)
    #c.startServer=siteConfig.cmdRegEx('\"vncserver -geometry {resolution}\"','^.*?started on display \S+(?P<vncDisplay>:[0-9]+)\s*$')
    c.startServer=siteConfig.cmdRegEx('\" rm -f ~/.vnc/clearpass ; touch ~/.vnc/clearpass ; chmod 600 ~/.vnc/clearpass ; passwd=\"\'$\'\"( dd if=/dev/urandom bs=1 count=8 2>/dev/null | md5sum | cut -b 1-8 ) ; echo \"\'$\'\"passwd > ~/.vnc/clearpass ; cat ~/.vnc/clearpass | vncpasswd -f > ~/.vnc/passwd ; chmod 600 ~/.vnc/passwd ; vncserver -geometry {resolution}\"','^.*?desktop is \S+(?P<vncDisplay>:[0-9]+)\s*$')
    c.stop=siteConfig.cmdRegEx('\'vncserver -kill {vncDisplay}\'')
    c.stopForRestart=siteConfig.cmdRegEx('\'vncserver -kill {vncDisplay}\'')
    #c.otp= siteConfig.cmdRegEx('\'vncpasswd -o -display localhost{vncDisplay}\'','^\s*Full control one-time password: (?P<vncPasswd>[0-9]+)\s*$')
    c.otp= siteConfig.cmdRegEx('\'echo "vncpasswd:" `cat ~/.vnc/clearpass`\'','^vncpasswd: (?P<vncPasswd>\S+)$')
    c.agent=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -l {username} {loginHost} "echo agent_hello; bash "','agent_hello',async=True)
    c.tunnel=siteConfig.cmdRegEx('{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -L {localPortNumber}:localhost:{remotePortNumber} -l {username} {loginHost} "echo tunnel_hello; bash"','tunnel_hello',async=True)

    cmd='"export DISPLAY={vncDisplay};timeout 15 /usr/local/bin/cat_dbus_session_file.sh"'
    regex='^DBUS_SESSION_BUS_ADDRESS=(?P<dbusSessionBusAddress>.*)$'
    c.dbusSessionBusAddress=siteConfig.cmdRegEx(cmd,regex)

    cmd='\"/usr/local/bin/get_ephemeral_port.py\"'
    regex='^(?P<remoteWebDavPortNumber>[0-9]+)$'
    c.webDavRemotePort=siteConfig.cmdRegEx(cmd,regex)

    cmd='{sshBinary} -A -c {cipher} -t -t -oStrictHostKeyChecking=no -oExitOnForwardFailure=yes -R {remoteWebDavPortNumber}:localhost:{localWebDavPortNumber} -l {username} {loginHost} \'echo tunnel_hello; bash\''
    regex='tunnel_hello'
    c.webDavTunnel=siteConfig.cmdRegEx(cmd,regex,async=True)

    cmd="\"/usr/bin/ssh -oStrictHostKeyChecking=no localhost \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};echo \\\\\\\"import pexpect;child = pexpect.spawn('gvfs-mount dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}');child.expect('Password: ');child.sendline('{vncPasswd}');child.expect(pexpect.EOF);child.close();print 'gvfs-mount returned ' + str(child.exitstatus)\\\\\\\" {pipe} python\\\"\"" 
    regex='^gvfs-mount returned (?P<webDavMountingExitCode>.*)$'
    c.webDavMount=siteConfig.cmdRegEx(cmd,regex)

    cmd="\"/usr/bin/ssh -oStrictHostKeyChecking=no localhost \\\"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};/usr/bin/gconftool-2 --type=Boolean --set /apps/nautilus/preferences/always_use_location_entry true {ampersand}{ampersand} DISPLAY={vncDisplay} xdg-open dav://{localUsername}@localhost:{remoteWebDavPortNumber}/{homeDirectoryWebDavShareName}\\\"\"" 
    c.openWebDavShareInRemoteFileBrowser=siteConfig.cmdRegEx(cmd)

    cmd='"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress}; DISPLAY={vncDisplay} xwininfo -root -tree"'
    regex= '^\s+(?P<webDavWindowID>\S+)\s+"{homeDirectoryWebDavShareName}.*Browser.*$'
    c.webDavWindowID=siteConfig.cmdRegEx(cmd,regex)

    # 1. I'm using gvfs-mount --unmount-scheme dav for now, to unmount all GVFS WebDAV mounts,
    #    because using "gvfs-mount --unmount " on a specific mount point from a Launcher
    #    subprocess doesn't seem to work reliably, even though it works fine outside of the 
    #    Launcher.
    # 2. I'm using timeout with gvfs-mount, because sometimes the process never exits
    #    when unmounting, even though the unmounting operation is complete.
    cmd = '"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay};timeout 1 gvfs-mount --unmount-scheme dav"'
    c.webDavUnmount=siteConfig.cmdRegEx(cmd)

    cmd = '"export DBUS_SESSION_BUS_ADDRESS={dbusSessionBusAddress};export DISPLAY={vncDisplay}; wmctrl -F -i -c {webDavWindowID}"'
    c.webDavCloseWindow=siteConfig.cmdRegEx(cmd)
    return c



import utilityFunctions
import json
defaultSites=collections.OrderedDict()
defaultSites['Desktop on m1-login2.massive.org.au']  = getMassiveSiteConfig("m1-login2.massive.org.au") 
defaultSites['Desktop on m2-login2.massive.org.au'] = getMassiveSiteConfig("m2-login2.massive.org.au") 
defaultSites['Desktop on m1-login1.massive.org.au']  = getMassiveSiteConfig("m1-login1.massive.org.au") 
defaultSites['Desktop on m2-login1.massive.org.au'] = getMassiveSiteConfig("m2-login1.massive.org.au") 
keys=defaultSites.keys()
jsons=json.dumps([keys,defaultSites],cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',', ': '))
with open('massive_flavours_20140408.json','w') as f:
    f.write(jsons)

defaultSites=collections.OrderedDict()
defaultSites['CVL Desktop']=  getCVLSiteConfig("batch")
defaultSites['Huygens on the CVL']= getCVLSiteConfig("huygens")
defaultSites['CVL GPU node']= getCVLSiteConfig("vis")

multicpu=getCVLSiteConfig("multicpu")
cmd="\"module load pbs ; module load maui ; echo \'module load pbs ; /usr/local/bin/vncsession --vnc turbovnc --geometry {resolution} ; sleep 36000000 \' |  qsub -q multicpu -l nodes=1:ppn=16 -l walltime=48:00:00 -N desktop_{username} -o .vnc/ -e .vnc/ \""
regex="^(?P<jobid>(?P<jobidNumber>[0-9]+)\.\S+)\s*$"
multicpu.startServer=siteConfig.cmdRegEx(cmd,regex)
defaultSites['CVL 16 core node']=multicpu

keys=defaultSites.keys()
jsons=json.dumps([keys,defaultSites],cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',', ': '))
with open('cvl_flavours.json','w') as f:
    f.write(jsons)

defaultSites=collections.OrderedDict()
defaultSites['Other']=getGenericVNCSession()
defaultSites['Other TurboVNC']=getOtherTurboVNCConfig("")
keys=defaultSites.keys()
jsons=json.dumps([keys,defaultSites],cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',', ': '))
with open('other_flavour.json','w') as f:
    f.write(jsons)

defaultSites=collections.OrderedDict()
newton=getGenericVNCSession()
gpu=getCQUGPUConfig("")
newton.visibility['loginHostPanel']=False
newton.loginHost="newton.cqu.edu.au"
isaac=getGenericVNCSession()
isaac.visibility['loginHostPanel']=False
isaac.loginHost="isaac.cqu.edu.au"
defaultSites['Isaac']=isaac
defaultSites['Newton']=newton
defaultSites['GPU']=gpu
keys=defaultSites.keys()
jsons=json.dumps([keys,defaultSites],cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',', ': '))
with open('cqu.json','w') as f:
    f.write(jsons)

defaultSites=collections.OrderedDict()
raijinExpress=getRaijinSiteConfig('express')
defaultSites['Raijin (Express Queue)'] = raijinExpress
defaultSites['Raijin (Login node raijin1)'] = getRaijinLoginSiteConfig('raijin1.nci.org.au')
defaultSites['Raijin (Login node raijin2)'] = getRaijinLoginSiteConfig('raijin2.nci.org.au')
keys=defaultSites.keys()
jsons=json.dumps([keys,defaultSites],cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',', ': '))
with open('nci_flavours.json','w') as f:
    f.write(jsons)

defaultSites=collections.OrderedDict()
defaultSites['CVL DesktopDev']=  getCVLSiteConfigXML("desktopdev")
keys=defaultSites.keys()
jsons=json.dumps([keys,defaultSites],cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',', ': '))
with open('cvl_dev_flavours.json','w') as f:
    f.write(jsons)
